package backup

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Destination defines the interface for backup destinations
type Destination interface {
	Upload(ctx context.Context, filePath string, config *DestinationConfig) (string, error)
	Download(ctx context.Context, remotePath string, localPath string, config *DestinationConfig) error
	Delete(ctx context.Context, remotePath string, config *DestinationConfig) error
	List(ctx context.Context, config *DestinationConfig) ([]RemoteFile, error)
	Validate(config *DestinationConfig) error
}

// DestinationConfig contains configuration for backup destinations
type DestinationConfig struct {
	Name       string                 `json:"name"`
	Type       DestinationType        `json:"type"`
	Path       string                 `json:"path"`
	Config     map[string]interface{} `json:"config"`
	Encryption bool                   `json:"encryption"`
	Retention  RetentionPolicy        `json:"retention"`
}

// DestinationType represents the type of backup destination
type DestinationType string

const (
	DestinationTypeLocal  DestinationType = "local"
	DestinationTypeS3     DestinationType = "s3"
	DestinationTypeSFTP   DestinationType = "sftp"
	DestinationTypeNFS    DestinationType = "nfs"
)

// RemoteFile represents a file in a remote destination
type RemoteFile struct {
	Name         string    `json:"name"`
	Path         string    `json:"path"`
	Size         int64     `json:"size"`
	ModifiedTime time.Time `json:"modified_time"`
	Checksum     string    `json:"checksum,omitempty"`
}

// LocalDestination implements local filesystem backup destination
type LocalDestination struct{}

// NewLocalDestination creates a new local destination
func NewLocalDestination() *LocalDestination {
	return &LocalDestination{}
}

// Upload uploads a file to local destination
func (d *LocalDestination) Upload(ctx context.Context, filePath string, config *DestinationConfig) (string, error) {
	// Ensure destination directory exists
	destDir := config.Path
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Generate destination filename (remove .tmp extension if present)
	filename := filepath.Base(filePath)
	if strings.HasSuffix(filename, ".tmp") {
		filename = strings.TrimSuffix(filename, ".tmp")
	}
	destPath := filepath.Join(destDir, filename)

	// Copy file
	src, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open source file: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(destPath)
	if err != nil {
		return "", fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return "", fmt.Errorf("failed to copy file: %w", err)
	}

	return destPath, nil
}

// Download downloads a file from local destination
func (d *LocalDestination) Download(ctx context.Context, remotePath string, localPath string, config *DestinationConfig) error {
	src, err := os.Open(remotePath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer src.Close()

	// Ensure local directory exists
	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		return fmt.Errorf("failed to create local directory: %w", err)
	}

	dst, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	return nil
}

// Delete deletes a file from local destination
func (d *LocalDestination) Delete(ctx context.Context, remotePath string, config *DestinationConfig) error {
	return os.Remove(remotePath)
}

// List lists files in local destination
func (d *LocalDestination) List(ctx context.Context, config *DestinationConfig) ([]RemoteFile, error) {
	var files []RemoteFile

	err := filepath.Walk(config.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(info.Name(), ".backup") {
			files = append(files, RemoteFile{
				Name:         info.Name(),
				Path:         path,
				Size:         info.Size(),
				ModifiedTime: info.ModTime(),
			})
		}

		return nil
	})

	return files, err
}

// Validate validates local destination configuration
func (d *LocalDestination) Validate(config *DestinationConfig) error {
	if config.Path == "" {
		return fmt.Errorf("path is required for local destination")
	}

	// Check if path is writable
	testFile := filepath.Join(config.Path, ".write_test")
	if err := os.MkdirAll(config.Path, 0755); err != nil {
		return fmt.Errorf("cannot create destination directory: %w", err)
	}

	file, err := os.Create(testFile)
	if err != nil {
		return fmt.Errorf("destination path is not writable: %w", err)
	}
	file.Close()
	os.Remove(testFile)

	return nil
}

// S3Destination implements AWS S3 backup destination
type S3Destination struct {
	session *session.Session
}

// NewS3Destination creates a new S3 destination
func NewS3Destination() *S3Destination {
	return &S3Destination{}
}

// Upload uploads a file to S3
func (d *S3Destination) Upload(ctx context.Context, filePath string, config *DestinationConfig) (string, error) {
	if d.session == nil {
		sess, err := session.NewSession(&aws.Config{
			Region: aws.String(d.getConfigString(config, "region", "us-east-1")),
		})
		if err != nil {
			return "", fmt.Errorf("failed to create AWS session: %w", err)
		}
		d.session = sess
	}

	svc := s3.New(d.session)
	bucket := d.getConfigString(config, "bucket", "")
	if bucket == "" {
		return "", fmt.Errorf("S3 bucket is required")
	}

	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Generate S3 key
	filename := filepath.Base(filePath)
	key := filepath.Join(config.Path, filename)

	// Upload to S3
	_, err = svc.PutObjectWithContext(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   file,
	})
	if err != nil {
		return "", fmt.Errorf("failed to upload to S3: %w", err)
	}

	return fmt.Sprintf("s3://%s/%s", bucket, key), nil
}

// Download downloads a file from S3
func (d *S3Destination) Download(ctx context.Context, remotePath string, localPath string, config *DestinationConfig) error {
	if d.session == nil {
		sess, err := session.NewSession(&aws.Config{
			Region: aws.String(d.getConfigString(config, "region", "us-east-1")),
		})
		if err != nil {
			return fmt.Errorf("failed to create AWS session: %w", err)
		}
		d.session = sess
	}

	svc := s3.New(d.session)

	// Parse S3 URL
	u, err := url.Parse(remotePath)
	if err != nil {
		return fmt.Errorf("invalid S3 URL: %w", err)
	}

	bucket := u.Host
	key := strings.TrimPrefix(u.Path, "/")

	// Download from S3
	result, err := svc.GetObjectWithContext(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("failed to download from S3: %w", err)
	}
	defer result.Body.Close()

	// Ensure local directory exists
	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		return fmt.Errorf("failed to create local directory: %w", err)
	}

	// Create local file
	file, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer file.Close()

	// Copy data
	if _, err := io.Copy(file, result.Body); err != nil {
		return fmt.Errorf("failed to copy data: %w", err)
	}

	return nil
}

// Delete deletes a file from S3
func (d *S3Destination) Delete(ctx context.Context, remotePath string, config *DestinationConfig) error {
	if d.session == nil {
		sess, err := session.NewSession(&aws.Config{
			Region: aws.String(d.getConfigString(config, "region", "us-east-1")),
		})
		if err != nil {
			return fmt.Errorf("failed to create AWS session: %w", err)
		}
		d.session = sess
	}

	svc := s3.New(d.session)

	// Parse S3 URL
	u, err := url.Parse(remotePath)
	if err != nil {
		return fmt.Errorf("invalid S3 URL: %w", err)
	}

	bucket := u.Host
	key := strings.TrimPrefix(u.Path, "/")

	// Delete from S3
	_, err = svc.DeleteObjectWithContext(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("failed to delete from S3: %w", err)
	}

	return nil
}

// List lists files in S3 destination
func (d *S3Destination) List(ctx context.Context, config *DestinationConfig) ([]RemoteFile, error) {
	if d.session == nil {
		sess, err := session.NewSession(&aws.Config{
			Region: aws.String(d.getConfigString(config, "region", "us-east-1")),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create AWS session: %w", err)
		}
		d.session = sess
	}

	svc := s3.New(d.session)
	bucket := d.getConfigString(config, "bucket", "")
	if bucket == "" {
		return nil, fmt.Errorf("S3 bucket is required")
	}

	// List objects
	result, err := svc.ListObjectsV2WithContext(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(config.Path),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list S3 objects: %w", err)
	}

	var files []RemoteFile
	for _, obj := range result.Contents {
		if strings.HasSuffix(*obj.Key, ".backup") {
			files = append(files, RemoteFile{
				Name:         filepath.Base(*obj.Key),
				Path:         fmt.Sprintf("s3://%s/%s", bucket, *obj.Key),
				Size:         *obj.Size,
				ModifiedTime: *obj.LastModified,
			})
		}
	}

	return files, nil
}

// Validate validates S3 destination configuration
func (d *S3Destination) Validate(config *DestinationConfig) error {
	bucket := d.getConfigString(config, "bucket", "")
	if bucket == "" {
		return fmt.Errorf("S3 bucket is required")
	}

	region := d.getConfigString(config, "region", "us-east-1")

	// Test AWS credentials and bucket access
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	if err != nil {
		return fmt.Errorf("failed to create AWS session: %w", err)
	}

	svc := s3.New(sess)
	_, err = svc.HeadBucket(&s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		return fmt.Errorf("cannot access S3 bucket: %w", err)
	}

	return nil
}

func (d *S3Destination) getConfigString(config *DestinationConfig, key, defaultValue string) string {
	if val, ok := config.Config[key].(string); ok {
		return val
	}
	return defaultValue
}

// SFTPDestination implements SFTP backup destination
type SFTPDestination struct {
	client *sftp.Client
	sshClient *ssh.Client
}

// NewSFTPDestination creates a new SFTP destination
func NewSFTPDestination() *SFTPDestination {
	return &SFTPDestination{}
}

// Upload uploads a file via SFTP
func (d *SFTPDestination) Upload(ctx context.Context, filePath string, config *DestinationConfig) (string, error) {
	if err := d.connect(config); err != nil {
		return "", fmt.Errorf("failed to connect to SFTP: %w", err)
	}
	defer d.disconnect()

	// Open local file
	src, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open source file: %w", err)
	}
	defer src.Close()

	// Generate remote path
	filename := filepath.Base(filePath)
	remotePath := filepath.Join(config.Path, filename)

	// Ensure remote directory exists
	if err := d.client.MkdirAll(filepath.Dir(remotePath)); err != nil {
		return "", fmt.Errorf("failed to create remote directory: %w", err)
	}

	// Create remote file
	dst, err := d.client.Create(remotePath)
	if err != nil {
		return "", fmt.Errorf("failed to create remote file: %w", err)
	}
	defer dst.Close()

	// Copy data
	if _, err := io.Copy(dst, src); err != nil {
		return "", fmt.Errorf("failed to copy data: %w", err)
	}

	return remotePath, nil
}

// Download downloads a file via SFTP
func (d *SFTPDestination) Download(ctx context.Context, remotePath string, localPath string, config *DestinationConfig) error {
	if err := d.connect(config); err != nil {
		return fmt.Errorf("failed to connect to SFTP: %w", err)
	}
	defer d.disconnect()

	// Open remote file
	src, err := d.client.Open(remotePath)
	if err != nil {
		return fmt.Errorf("failed to open remote file: %w", err)
	}
	defer src.Close()

	// Ensure local directory exists
	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		return fmt.Errorf("failed to create local directory: %w", err)
	}

	// Create local file
	dst, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer dst.Close()

	// Copy data
	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("failed to copy data: %w", err)
	}

	return nil
}

// Delete deletes a file via SFTP
func (d *SFTPDestination) Delete(ctx context.Context, remotePath string, config *DestinationConfig) error {
	if err := d.connect(config); err != nil {
		return fmt.Errorf("failed to connect to SFTP: %w", err)
	}
	defer d.disconnect()

	return d.client.Remove(remotePath)
}

// List lists files via SFTP
func (d *SFTPDestination) List(ctx context.Context, config *DestinationConfig) ([]RemoteFile, error) {
	if err := d.connect(config); err != nil {
		return nil, fmt.Errorf("failed to connect to SFTP: %w", err)
	}
	defer d.disconnect()

	entries, err := d.client.ReadDir(config.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read remote directory: %w", err)
	}

	var files []RemoteFile
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".backup") {
			files = append(files, RemoteFile{
				Name:         entry.Name(),
				Path:         filepath.Join(config.Path, entry.Name()),
				Size:         entry.Size(),
				ModifiedTime: entry.ModTime(),
			})
		}
	}

	return files, nil
}

// Validate validates SFTP destination configuration
func (d *SFTPDestination) Validate(config *DestinationConfig) error {
	host := d.getConfigString(config, "host", "")
	if host == "" {
		return fmt.Errorf("SFTP host is required")
	}

	username := d.getConfigString(config, "username", "")
	if username == "" {
		return fmt.Errorf("SFTP username is required")
	}

	// Test connection
	if err := d.connect(config); err != nil {
		return fmt.Errorf("failed to connect to SFTP server: %w", err)
	}
	d.disconnect()

	return nil
}

func (d *SFTPDestination) connect(config *DestinationConfig) error {
	if d.client != nil {
		return nil // Already connected
	}

	host := d.getConfigString(config, "host", "")
	port := d.getConfigString(config, "port", "22")
	username := d.getConfigString(config, "username", "")
	password := d.getConfigString(config, "password", "")
	keyPath := d.getConfigString(config, "private_key_path", "")

	var auth []ssh.AuthMethod

	// Use private key if provided
	if keyPath != "" {
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("failed to read private key: %w", err)
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}

		auth = append(auth, ssh.PublicKeys(signer))
	}

	// Use password if provided
	if password != "" {
		auth = append(auth, ssh.Password(password))
	}

	if len(auth) == 0 {
		return fmt.Errorf("no authentication method provided")
	}

	// Connect to SSH server
	sshClient, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", host, port), &ssh.ClientConfig{
		User:            username,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // In production, use proper host key verification
	})
	if err != nil {
		return fmt.Errorf("failed to connect to SSH server: %w", err)
	}

	// Create SFTP client
	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		sshClient.Close()
		return fmt.Errorf("failed to create SFTP client: %w", err)
	}

	d.sshClient = sshClient
	d.client = sftpClient

	return nil
}

func (d *SFTPDestination) disconnect() {
	if d.client != nil {
		d.client.Close()
		d.client = nil
	}
	if d.sshClient != nil {
		d.sshClient.Close()
		d.sshClient = nil
	}
}

func (d *SFTPDestination) getConfigString(config *DestinationConfig, key, defaultValue string) string {
	if val, ok := config.Config[key].(string); ok {
		return val
	}
	return defaultValue
}