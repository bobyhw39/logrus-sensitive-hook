package sensitivehook

import (
	"fmt"
	"github.com/bobyhw39/logrus-sensitive-hook/dataprocessor"
	"github.com/sirupsen/logrus"
	"reflect"
	"regexp"
)

type SensitiveFormatter struct {
	logrus.Formatter
	DataProcessor dataprocessor.DataProcessor
	FieldNameList []string
}

func (f *SensitiveFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	data := make(logrus.Fields, len(entry.Data))
	for k, v := range entry.Data {
		rv := reflect.ValueOf(v)
		if rv.Kind() == reflect.Struct {
			maskedData := f.hideSensitiveFields(rv)
			data[k] = maskedData
		} else {
			data[k] = v
		}
	}

	entry.Data = data
	return f.Formatter.Format(entry)
}

func (f *SensitiveFormatter) hideSensitiveFields(rv reflect.Value) map[string]interface{} {
	rt := rv.Type()
	encryptedData := make(map[string]interface{})

	for i := 0; i < rv.NumField(); i++ {
		field := rv.Field(i)
		fieldType := rt.Field(i)

		if tag := fieldType.Tag.Get("log"); tag == "sensitive" || f.matchFromFieldNameList(fieldType.Name) {
			encryptedData[fieldType.Name] = f.DataProcessor.Process(fmt.Sprintf("%v", field.Interface()))
		} else {
			encryptedData[fieldType.Name] = field.Interface()
		}
	}

	return encryptedData
}

func (f *SensitiveFormatter) matchFromFieldNameList(key string) bool {
	for _, redactionKey := range f.FieldNameList {
		re, err := regexp.Compile(redactionKey)
		if err != nil {
			return false
		}
		return re.MatchString(key)
	}
	return false
}
