// Package vehicle 提供中国大陆车牌号校验。
//
// 正则在包级用 regexp.MustCompile 编译一次：模式是包内常量，不可能编译
// 失败，故不需要运行期错误分支——此前每次调用 regexp.Compile 既浪费，
// 又迫使调用方传 logger 进来打那条永不可达的错误日志。
package vehicle

import "regexp"

// Regular expression patterns
const (
	newEnergyPattern    = "^[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼][A-Z][DF]\\d{4}[DF]$"
	regularPlatePattern = "^[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼][A-Z][A-Z0-9]{5}$"
)

var (
	newEnergyRe    = regexp.MustCompile(newEnergyPattern)
	regularPlateRe = regexp.MustCompile(regularPlatePattern)
)

// ValidateLicenseNewPlate 校验中国大陆新能源汽车车牌号
func ValidateLicenseNewPlate(licensePlate string) bool {
	if len([]rune(licensePlate)) != 8 {
		return false
	}
	return newEnergyRe.MatchString(licensePlate)
}

// ValidateLicensePlate 验证中国大陆普通车牌号
func ValidateLicensePlate(licensePlate string) bool {
	if len([]rune(licensePlate)) != 7 {
		return false
	}
	return regularPlateRe.MatchString(licensePlate)
}

// ValidatePlate 验证车牌号，包括新能源和普通车牌号
func ValidatePlate(plate string) bool {
	switch len([]rune(plate)) {
	case 8:
		return ValidateLicenseNewPlate(plate)
	case 7:
		return ValidateLicensePlate(plate)
	default:
		return false
	}
}
