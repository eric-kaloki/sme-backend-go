package export

import (
	"encoding/csv"
	"fmt"
	"io"

	"github.com/xuri/excelize/v2"
)

// SheetData represents a single table of data
type SheetData struct {
	Name    string
	Headers []string
	Rows    [][]string
}

// WriteCSV exports a single slice of tabular data to an io.Writer in standard CSV format.
func WriteCSV(w io.Writer, headers []string, rows [][]string) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	if err := writer.Write(headers); err != nil {
		return err
	}
	for _, row := range rows {
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// WriteStackedCSV exports multiple slices of data to a single CSV by inserting blank lines between tables.
func WriteStackedCSV(w io.Writer, sheets []SheetData) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	for i, sheet := range sheets {
		if len(sheet.Headers) == 0 && len(sheet.Rows) == 0 {
			continue
		}

		// Title line
		if err := writer.Write([]string{sheet.Name}); err != nil {
			return err
		}
		// Headers
		if len(sheet.Headers) > 0 {
			if err := writer.Write(sheet.Headers); err != nil {
				return err
			}
		}
		// Rows
		for _, row := range sheet.Rows {
			if err := writer.Write(row); err != nil {
				return err
			}
		}

		// Spacer gap before next section
		if i < len(sheets)-1 {
			writer.Write([]string{})
			writer.Write([]string{})
		}
	}
	return nil
}

// WriteExcel exports tabular data spanning multiple sheets (or a single default sheet) to an io.Writer.
func WriteExcel(w io.Writer, sheets []SheetData) error {
	f := excelize.NewFile()
	defer f.Close()

	if len(sheets) == 0 {
		return f.Write(w)
	}

	for i, sheet := range sheets {
		sheetName := sheet.Name
		if sheetName == "" {
			sheetName = "Sheet1"
		}

		// The default active sheet created by NewFile is "Sheet1".
		// For subsequent tabs, we need to create them.
		if i == 0 && sheetName != "Sheet1" {
			f.SetSheetName("Sheet1", sheetName)
		} else if i > 0 {
			if _, err := f.NewSheet(sheetName); err != nil {
				return err
			}
		}

		// Write Headers to Row 1
		for colIdx, header := range sheet.Headers {
			cell, _ := excelize.CoordinatesToCellName(colIdx+1, 1)
			f.SetCellValue(sheetName, cell, header)
		}

		// Write Content starting Row 2
		for rowIdx, row := range sheet.Rows {
			for colIdx, val := range row {
				cell, _ := excelize.CoordinatesToCellName(colIdx+1, rowIdx+2)
				f.SetCellValue(sheetName, cell, val)
			}
		}

		// Style headers
		style, err := f.NewStyle(&excelize.Style{
			Font: &excelize.Font{Bold: true, Color: "#FFFFFF"},
			Fill: excelize.Fill{Type: "pattern", Color: []string{"#4F81BD"}, Pattern: 1},
		})
		if err == nil && len(sheet.Headers) > 0 {
			endCell, _ := excelize.CoordinatesToCellName(len(sheet.Headers), 1)
			f.SetCellStyle(sheetName, "A1", endCell, style)
		}
	}

	return f.Write(w)
}

func FormatStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func FormatAny(val interface{}) string {
	if val == nil {
		return ""
	}
	return fmt.Sprintf("%v", val)
}
