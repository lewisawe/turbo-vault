package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// OutputFormat represents the output format type
type OutputFormat string

const (
	OutputJSON  OutputFormat = "json"
	OutputYAML  OutputFormat = "yaml"
	OutputTable OutputFormat = "table"
)

// Printer handles output formatting and printing
type Printer struct {
	Format OutputFormat
	Writer *tabwriter.Writer
}

// NewPrinter creates a new output printer
func NewPrinter() *Printer {
	format := OutputFormat(viper.GetString("output"))
	if format == "" {
		format = OutputTable
	}

	return &Printer{
		Format: format,
		Writer: tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0),
	}
}

// Print outputs data in the specified format
func (p *Printer) Print(data interface{}) error {
	switch p.Format {
	case OutputJSON:
		return p.printJSON(data)
	case OutputYAML:
		return p.printYAML(data)
	case OutputTable:
		return p.printTable(data)
	default:
		return fmt.Errorf("unsupported output format: %s", p.Format)
	}
}

// printJSON outputs data as JSON
func (p *Printer) printJSON(data interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// printYAML outputs data as YAML
func (p *Printer) printYAML(data interface{}) error {
	encoder := yaml.NewEncoder(os.Stdout)
	defer encoder.Close()
	return encoder.Encode(data)
}

// printTable outputs data as a formatted table
func (p *Printer) printTable(data interface{}) error {
	defer p.Writer.Flush()

	// Handle different data types
	switch v := data.(type) {
	case []interface{}:
		return p.printSliceTable(v)
	case map[string]interface{}:
		return p.printMapTable(v)
	default:
		// Use reflection for struct types
		return p.printStructTable(data)
	}
}

// printSliceTable prints a slice as a table
func (p *Printer) printSliceTable(data []interface{}) error {
	if len(data) == 0 {
		fmt.Println("No data found")
		return nil
	}

	// Get headers from first item
	first := data[0]
	headers := p.getHeaders(first)
	
	// Print headers
	fmt.Fprint(p.Writer, strings.Join(headers, "\t"))
	fmt.Fprint(p.Writer, "\n")

	// Print separator
	separators := make([]string, len(headers))
	for i := range separators {
		separators[i] = strings.Repeat("-", len(headers[i]))
	}
	fmt.Fprint(p.Writer, strings.Join(separators, "\t"))
	fmt.Fprint(p.Writer, "\n")

	// Print rows
	for _, item := range data {
		values := p.getValues(item, headers)
		fmt.Fprint(p.Writer, strings.Join(values, "\t"))
		fmt.Fprint(p.Writer, "\n")
	}

	return nil
}

// printMapTable prints a map as a key-value table
func (p *Printer) printMapTable(data map[string]interface{}) error {
	fmt.Fprint(p.Writer, "KEY\tVALUE\n")
	fmt.Fprint(p.Writer, "---\t-----\n")

	for key, value := range data {
		valueStr := p.formatValue(value)
		fmt.Fprintf(p.Writer, "%s\t%s\n", key, valueStr)
	}

	return nil
}

// printStructTable prints a struct as a table using reflection
func (p *Printer) printStructTable(data interface{}) error {
	v := reflect.ValueOf(data)
	t := reflect.TypeOf(data)

	// Handle pointers
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
		t = t.Elem()
	}

	// Handle slices
	if v.Kind() == reflect.Slice {
		if v.Len() == 0 {
			fmt.Println("No data found")
			return nil
		}

		// Get field names from first element
		firstElem := v.Index(0)
		firstType := firstElem.Type()
		if firstElem.Kind() == reflect.Ptr {
			firstElem = firstElem.Elem()
			firstType = firstType.Elem()
		}

		var headers []string
		for i := 0; i < firstType.NumField(); i++ {
			field := firstType.Field(i)
			if field.IsExported() {
				headers = append(headers, strings.ToUpper(field.Name))
			}
		}

		// Print headers
		fmt.Fprint(p.Writer, strings.Join(headers, "\t"))
		fmt.Fprint(p.Writer, "\n")

		// Print separator
		separators := make([]string, len(headers))
		for i := range separators {
			separators[i] = strings.Repeat("-", len(headers[i]))
		}
		fmt.Fprint(p.Writer, strings.Join(separators, "\t"))
		fmt.Fprint(p.Writer, "\n")

		// Print rows
		for i := 0; i < v.Len(); i++ {
			elem := v.Index(i)
			if elem.Kind() == reflect.Ptr {
				elem = elem.Elem()
			}

			var values []string
			for j := 0; j < elem.NumField(); j++ {
				field := elem.Field(j)
				if field.CanInterface() {
					values = append(values, p.formatValue(field.Interface()))
				}
			}

			fmt.Fprint(p.Writer, strings.Join(values, "\t"))
			fmt.Fprint(p.Writer, "\n")
		}

		return nil
	}

	// Handle single struct
	fmt.Fprint(p.Writer, "FIELD\tVALUE\n")
	fmt.Fprint(p.Writer, "-----\t-----\n")

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.IsExported() {
			value := v.Field(i)
			if value.CanInterface() {
				fmt.Fprintf(p.Writer, "%s\t%s\n", field.Name, p.formatValue(value.Interface()))
			}
		}
	}

	return nil
}

// getHeaders extracts headers from a data structure
func (p *Printer) getHeaders(data interface{}) []string {
	switch v := data.(type) {
	case map[string]interface{}:
		var headers []string
		for key := range v {
			headers = append(headers, strings.ToUpper(key))
		}
		return headers
	default:
		// Use reflection for struct types
		val := reflect.ValueOf(data)
		typ := reflect.TypeOf(data)

		if val.Kind() == reflect.Ptr {
			val = val.Elem()
			typ = typ.Elem()
		}

		var headers []string
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.IsExported() {
				headers = append(headers, strings.ToUpper(field.Name))
			}
		}
		return headers
	}
}

// getValues extracts values from a data structure based on headers
func (p *Printer) getValues(data interface{}, headers []string) []string {
	var values []string

	switch v := data.(type) {
	case map[string]interface{}:
		for _, header := range headers {
			key := strings.ToLower(header)
			if value, exists := v[key]; exists {
				values = append(values, p.formatValue(value))
			} else {
				values = append(values, "")
			}
		}
	default:
		// Use reflection for struct types
		val := reflect.ValueOf(data)
		if val.Kind() == reflect.Ptr {
			val = val.Elem()
		}

		for i := 0; i < val.NumField(); i++ {
			field := val.Field(i)
			if field.CanInterface() {
				values = append(values, p.formatValue(field.Interface()))
			}
		}
	}

	return values
}

// formatValue formats a value for display
func (p *Printer) formatValue(value interface{}) string {
	if value == nil {
		return ""
	}

	switch v := value.(type) {
	case string:
		return v
	case time.Time:
		return v.Format("2006-01-02 15:04:05")
	case *time.Time:
		if v == nil {
			return ""
		}
		return v.Format("2006-01-02 15:04:05")
	case bool:
		if v {
			return "true"
		}
		return "false"
	case []string:
		return strings.Join(v, ", ")
	case map[string]interface{}:
		// For complex objects, show a summary
		return fmt.Sprintf("<%d fields>", len(v))
	default:
		return fmt.Sprintf("%v", value)
	}
}

// PrintSuccess prints a success message
func PrintSuccess(message string) {
	fmt.Printf("✓ %s\n", message)
}

// PrintError prints an error message
func PrintError(message string) {
	fmt.Fprintf(os.Stderr, "✗ Error: %s\n", message)
}

// PrintWarning prints a warning message
func PrintWarning(message string) {
	fmt.Printf("⚠ Warning: %s\n", message)
}

// PrintInfo prints an info message
func PrintInfo(message string) {
	if viper.GetBool("verbose") {
		fmt.Printf("ℹ %s\n", message)
	}
}