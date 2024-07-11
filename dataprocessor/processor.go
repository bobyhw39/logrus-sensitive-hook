package dataprocessor

type DataProcessor interface {
	Process(data string) string
}
