//go:build !windows && !linux

package project

import "os"

// 01: Other platforms are explicitly unsupported, never weakly emulated.
func openAbsoluteDirectory(string) (*safeDir, []fileIdentity, error) {
	return nil, nil, ErrUnsupportedPlatform
}
func fileState(*os.File) (fileStamp, error) { return fileStamp{}, ErrUnsupportedPlatform }
func openChild(*safeDir, string) (*os.File, fileStamp, error) {
	return nil, fileStamp{}, ErrUnsupportedPlatform
}
func openRelative(*safeDir, string) (*os.File, fileStamp, error) {
	return nil, fileStamp{}, ErrUnsupportedPlatform
}
func reopenDirectory(*safeDir) (*safeDir, error)             { return nil, ErrUnsupportedPlatform }
func validateRootRelationship(*safeDir, *safeDir) error      { return ErrUnsupportedPlatform }
func validateDestinationParent(*safeDir) error               { return ErrUnsupportedPlatform }
func createDirectory(*safeDir, string) (*safeDir, error)     { return nil, ErrUnsupportedPlatform }
func createFile(*safeDir, string) (*os.File, error)          { return nil, ErrUnsupportedPlatform }
func removeChild(*safeDir, string, fileIdentity, bool) error { return ErrUnsupportedPlatform }
