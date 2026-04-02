//go:build cgo && darwin

// Copyright (c) Smallstep Labs, Inc.
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.
//
// Part of this code is based on
// https://github.com/facebookincubator/sks/blob/183e7561ecedc71992f23b2d37983d2948391f4c/macos/macos.go

//nolint:gocritic // open issue https://github.com/go-critic/go-critic/issues/845
package security

/*
// Enable Automatic Reference Counting (ARC) for Foundation objects,
// CoreFoundation objects must be manually managed.
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework CoreFoundation -framework Foundation -framework CoreWLAN -framework NetworkExtension -framework Security
#import <NetworkExtension/NetworkExtension.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>
*/
import "C"

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"unsafe"

	cf "github.com/smallstep/step-kms-plugin/internal/darwin/corefoundation"
)

const (
	nilSecKey           C.SecKeyRef           = 0
	nilSecIdentity      C.SecIdentityRef      = 0
	nilSecAccessControl C.SecAccessControlRef = 0
	nilCFString         C.CFStringRef         = 0
	nilCFData           C.CFDataRef           = 0
	nilCFTypeRef        C.CFTypeRef           = 0
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrInvalidData   = errors.New("invalid data")
)

var (
	KSecAttrAccessControl                            = cf.TypeRef(C.kSecAttrAccessControl)
	KSecAttrAccessGroup                              = cf.TypeRef(C.kSecAttrAccessGroup)
	KSecAttrAccessGroupToken                         = cf.TypeRef(C.kSecAttrAccessGroupToken)
	KSecAttrAccessibleWhenUnlocked                   = cf.TypeRef(C.kSecAttrAccessibleWhenUnlocked)
	KSecAttrAccessibleWhenPasscodeSetThisDeviceOnly  = cf.TypeRef(C.kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly)
	KSecAttrAccessibleWhenUnlockedThisDeviceOnly     = cf.TypeRef(C.kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
	KSecAttrAccessibleAfterFirstUnlock               = cf.TypeRef(C.kSecAttrAccessibleAfterFirstUnlock)
	KSecAttrAccessibleAfterFirstUnlockThisDeviceOnly = cf.TypeRef(C.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
	KSecAttrApplicationLabel                         = cf.TypeRef(C.kSecAttrApplicationLabel)
	KSecAttrApplicationTag                           = cf.TypeRef(C.kSecAttrApplicationTag)
	KSecAttrCanEncrypt                               = cf.TypeRef(C.kSecAttrCanEncrypt)
	KSecAttrCanDecrypt                               = cf.TypeRef(C.kSecAttrCanDecrypt)
	KSecAttrCanSign                                  = cf.TypeRef(C.kSecAttrCanSign)
	KSecAttrCanVerify                                = cf.TypeRef(C.kSecAttrCanVerify)
	KSecAttrCanWrap                                  = cf.TypeRef(C.kSecAttrCanWrap)
	KSecAttrCanUnwrap                                = cf.TypeRef(C.kSecAttrCanUnwrap)
	KSecAttrIsPermanent                              = cf.TypeRef(C.kSecAttrIsPermanent)
	KSecAttrKeyClass                                 = cf.TypeRef(C.kSecAttrKeyClass)
	KSecAttrKeyClassPrivate                          = cf.TypeRef(C.kSecAttrKeyClassPrivate)
	KSecAttrKeyClassPublic                           = cf.TypeRef(C.kSecAttrKeyClassPublic)
	KSecAttrKeySizeInBits                            = cf.TypeRef(C.kSecAttrKeySizeInBits)
	KSecAttrKeyType                                  = cf.TypeRef(C.kSecAttrKeyType)
	KSecAttrKeyTypeECSECPrimeRandom                  = cf.TypeRef(C.kSecAttrKeyTypeECSECPrimeRandom)
	KSecAttrKeyTypeRSA                               = cf.TypeRef(C.kSecAttrKeyTypeRSA)
	KSecAttrLabel                                    = cf.TypeRef(C.kSecAttrLabel)
	KSecAttrTokenID                                  = cf.TypeRef(C.kSecAttrTokenID)
	KSecAttrTokenIDSecureEnclave                     = cf.TypeRef(C.kSecAttrTokenIDSecureEnclave)
	KSecAttrSerialNumber                             = cf.TypeRef(C.kSecAttrSerialNumber)
	KSecAttrSubjectKeyID                             = cf.TypeRef(C.kSecAttrSubjectKeyID)
	KSecAttrSubject                                  = cf.TypeRef(C.kSecAttrSubject)
	KSecAttrIssuer                                   = cf.TypeRef(C.kSecAttrIssuer)
	KSecAttrSynchronizable                           = cf.TypeRef(C.kSecAttrSynchronizable)
	KSecUseDataProtectionKeychain                    = cf.TypeRef(C.kSecUseDataProtectionKeychain)
	KSecClass                                        = cf.TypeRef(C.kSecClass)
	KSecClassKey                                     = cf.TypeRef(C.kSecClassKey)
	KSecClassCertificate                             = cf.TypeRef(C.kSecClassCertificate)
	KSecClassIdentity                                = cf.TypeRef(C.kSecClassIdentity)
	KSecMatchLimit                                   = cf.TypeRef(C.kSecMatchLimit)
	KSecMatchLimitOne                                = cf.TypeRef(C.kSecMatchLimitOne)
	KSecMatchLimitAll                                = cf.TypeRef(C.kSecMatchLimitAll)
	KSecPublicKeyAttrs                               = cf.TypeRef(C.kSecPublicKeyAttrs)
	KSecPrivateKeyAttrs                              = cf.TypeRef(C.kSecPrivateKeyAttrs)
	KSecReturnRef                                    = cf.TypeRef(C.kSecReturnRef)
	KSecReturnAttributes                             = cf.TypeRef(C.kSecReturnAttributes)
	KSecValueRef                                     = cf.TypeRef(C.kSecValueRef)
	KSecValueData                                    = cf.TypeRef(C.kSecValueData)
)

type SecKeyAlgorithm = C.SecKeyAlgorithm

var (
	KSecKeyAlgorithmECDSASignatureDigestX962         = C.kSecKeyAlgorithmECDSASignatureDigestX962
	KSecKeyAlgorithmECDSASignatureDigestX962SHA256   = C.kSecKeyAlgorithmECDSASignatureDigestX962SHA256
	KSecKeyAlgorithmECDSASignatureDigestX962SHA384   = C.kSecKeyAlgorithmECDSASignatureDigestX962SHA384
	KSecKeyAlgorithmECDSASignatureDigestX962SHA512   = C.kSecKeyAlgorithmECDSASignatureDigestX962SHA512
	KSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256 = C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
	KSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384 = C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384
	KSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512 = C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512
	KSecKeyAlgorithmRSASignatureDigestPSSSHA256      = C.kSecKeyAlgorithmRSASignatureDigestPSSSHA256
	KSecKeyAlgorithmRSASignatureDigestPSSSHA384      = C.kSecKeyAlgorithmRSASignatureDigestPSSSHA384
	KSecKeyAlgorithmRSASignatureDigestPSSSHA512      = C.kSecKeyAlgorithmRSASignatureDigestPSSSHA512
	KSecKeyAlgorithmECDHKeyExchangeStandard          = C.kSecKeyAlgorithmECDHKeyExchangeStandard
)

type SecAccessControlCreateFlags = C.SecAccessControlCreateFlags

const (
	// Enable a private key to be used in signing a block of data or verifying a
	// signed block.
	KSecAccessControlPrivateKeyUsage = SecAccessControlCreateFlags(C.kSecAccessControlPrivateKeyUsage)

	// Option to use an application-provided password for data encryption key
	// generation.
	KSecAccessControlApplicationPassword = SecAccessControlCreateFlags(C.kSecAccessControlApplicationPassword)

	// Constraint to access an item with a passcode.
	KSecAccessControlDevicePasscode = SecAccessControlCreateFlags(C.kSecAccessControlDevicePasscode)

	// Constraint to access an item with Touch ID for any enrolled fingers, or
	// Face ID.
	KSecAccessControlBiometryAny = SecAccessControlCreateFlags(C.kSecAccessControlBiometryAny)

	// Constraint to access an item with Touch ID for currently enrolled
	// fingers, or from Face ID with the currently enrolled user.
	KSecAccessControlBiometryCurrentSet = SecAccessControlCreateFlags(C.kSecAccessControlBiometryCurrentSet)

	// Constraint to access an item with either biometry or passcode.
	KSecAccessControlUserPresence = SecAccessControlCreateFlags(C.kSecAccessControlUserPresence)

	// Constraint to access an item with a watch.
	KSecAccessControlWatch = SecAccessControlCreateFlags(C.kSecAccessControlWatch)

	// Indicates that all constraints must be satisfied.
	KSecAccessControlAnd = SecAccessControlCreateFlags(C.kSecAccessControlAnd)

	// Indicates that at least one constraint must be satisfied.
	KSecAccessControlOr = SecAccessControlCreateFlags(C.kSecAccessControlOr)
)

type SecKeychainItemRef struct {
	Value C.SecKeychainItemRef
}

func NewSecKeychainItemRef(ref cf.TypeRef) *SecKeychainItemRef {
	return &SecKeychainItemRef{
		Value: C.SecKeychainItemRef(ref),
	}
}

func (v *SecKeychainItemRef) Release()              { cf.Release(v) }
func (v *SecKeychainItemRef) TypeRef() cf.CFTypeRef { return cf.CFTypeRef(v.Value) }
func (v *SecKeychainItemRef) Retain()               { cf.Retain(v) }

type SecIdentityRef struct {
	Value C.SecIdentityRef
}

func NewSecIdentityRef(ref cf.TypeRef) *SecIdentityRef {
	return &SecIdentityRef{
		Value: C.SecIdentityRef(ref),
	}
}

func (v *SecIdentityRef) Release()              { cf.Release(v) }
func (v *SecIdentityRef) TypeRef() cf.CFTypeRef { return cf.CFTypeRef(v.Value) }
func (v *SecIdentityRef) Retain()               { cf.Retain(v) }

func (v *SecIdentityRef) SecKeyRef() (*SecKeyRef, error) {
	var ref SecKeyRef
	status := C.SecIdentityCopyPrivateKey(v.Value, &ref.Value)
	return &ref, goOSStatus(status)
}

func (v *SecIdentityRef) SecCertificateRef() (*SecCertificateRef, error) {
	var ref SecCertificateRef
	status := C.SecIdentityCopyCertificate(v.Value, &ref.Value)
	return &ref, goOSStatus(status)
}

type SecKeyRef struct {
	Value C.SecKeyRef
}

type SecKeySigner struct {
	ref *SecKeyRef
	pub crypto.PublicKey
}

func (s *SecKeySigner) Public() crypto.PublicKey {
	return s.pub
}

func (s *SecKeySigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	algo, err := getSecKeyAlgorithm(s.pub, opts)
	if err != nil {
		return nil, fmt.Errorf("SecKeyRef Sign failed: %w", err)
	}

	cfDigest, err := cf.NewData(digest)
	if err != nil {
		return nil, fmt.Errorf("SecKeyRef Sign failed: %w", err)
	}
	defer cfDigest.Release()

	signature, err := SecKeyCreateSignature(s.ref, algo, cfDigest)
	if err != nil {
		return nil, fmt.Errorf("SecKeyRef Sign failed: %w", err)
	}
	defer signature.Release()

	return signature.Bytes(), nil
}

func NewSecKeyRef(ref cf.TypeRef) *SecKeyRef {
	return &SecKeyRef{
		Value: C.SecKeyRef(ref),
	}
}

func (v *SecKeyRef) Release()              { cf.Release(v) }
func (v *SecKeyRef) TypeRef() cf.CFTypeRef { return cf.CFTypeRef(v.Value) }
func (v *SecKeyRef) Retain()               { cf.Retain(v) }

func (v *SecKeyRef) Signer() (crypto.Signer, error) {
	pub, _, err := v.Public()
	if err != nil {
		return nil, err
	}

	return &SecKeySigner{
		ref: v,
		pub: pub,
	}, nil
}

func (v *SecKeyRef) Public() (crypto.PublicKey, []byte, error) {
	// Get the hash of the public key. We can also calculate this from the
	// external representation below, but in case Apple decides to switch from
	// SHA-1, let's just use what macOS sets by default.
	attrs := SecKeyCopyAttributes(v)
	defer attrs.Release()
	hash := GetSecAttrApplicationLabel(attrs)

	// Attempt to extract the public key, it will fail if the app that created
	// the private key didn’t also store the corresponding public key in the
	// keychain, or if the system can’t reconstruct the corresponding public
	// key.
	if publicKey, err := SecKeyCopyPublicKey(v); err == nil {
		defer publicKey.Release()

		// For an unknown reason this sometimes fails with the error -25293
		// (errSecAuthFailed). If this happens attempt to extract the key from
		// the private key.
		if data, err := SecKeyCopyExternalRepresentation(publicKey); err == nil {
			defer data.Release()

			derBytes := data.Bytes()
			// ECDSA public keys are formatted as "04 || X || Y"
			if derBytes[0] == 0x04 {
				pub, err := parseECDSAPublicKey(derBytes)
				if err != nil {
					return nil, nil, fmt.Errorf("error parsing ECDSA key: %w", err)
				}
				return pub, hash, nil
			}

			// RSA public keys are formatted using PKCS #1
			pub, err := x509.ParsePKCS1PublicKey(derBytes)
			if err != nil {
				return nil, nil, fmt.Errorf("error parsing RSA key: %w", err)
			}

			return pub, hash, nil
		}
	}

	// At this point we only have the private key.
	data, err := SecKeyCopyExternalRepresentation(v)
	if err != nil {
		return nil, nil, fmt.Errorf("macOS SecKeyCopyExternalRepresentation failed: %w", err)
	}
	defer data.Release()

	derBytes := data.Bytes()

	// ECDSA private keys are formatted as "04 || X || Y || K"
	if derBytes[0] == 0x04 {
		pub, err := parseECDSAPrivateKey(derBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing ECDSA key: %w", err)
		}
		return pub, hash, nil
	}

	// RSA private keys are formatted using PKCS #1
	priv, err := x509.ParsePKCS1PrivateKey(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing key: %w", err)
	}
	return priv.Public(), hash, nil
}

type SecCertificateRef struct {
	Value C.SecCertificateRef
}

func NewSecCertificateRef(ref cf.TypeRef) *SecCertificateRef {
	return &SecCertificateRef{
		Value: C.SecCertificateRef(ref),
	}
}

func (v *SecCertificateRef) Release()              { cf.Release(v) }
func (v *SecCertificateRef) TypeRef() cf.CFTypeRef { return cf.CFTypeRef(v.Value) }

func (v *SecCertificateRef) Certificate() (*x509.Certificate, error) {
	data, err := SecCertificateCopyData(v)
	if err != nil {
		return nil, err
	}
	defer data.Release()

	cert, err := x509.ParseCertificate(data.Bytes())
	if err != nil {
		return nil, err
	}

	return cert, nil
}

type SecAccessControlRef struct {
	ref C.SecAccessControlRef
}

func (v *SecAccessControlRef) Release()              { cf.Release(v) }
func (v *SecAccessControlRef) TypeRef() cf.CFTypeRef { return cf.CFTypeRef(v.ref) }

func SecItemAdd(attributes *cf.DictionaryRef, result *cf.TypeRef) error {
	status := C.SecItemAdd(C.CFDictionaryRef(attributes.Value), (*C.CFTypeRef)(result))
	return goOSStatus(status)
}

func SecItemUpdate(query *cf.DictionaryRef, attributesToUpdate *cf.DictionaryRef) error {
	status := C.SecItemUpdate(C.CFDictionaryRef(query.Value), C.CFDictionaryRef(attributesToUpdate.Value))
	return goOSStatus(status)
}

func SecItemDelete(query *cf.DictionaryRef) error {
	status := C.SecItemDelete(C.CFDictionaryRef(query.Value))
	return goOSStatus(status)
}

func SecItemCopyMatching(query *cf.DictionaryRef, result *cf.TypeRef) error {
	status := C.SecItemCopyMatching(C.CFDictionaryRef(query.Value), (*C.CFTypeRef)(result))
	return goOSStatus(status)
}

func SecIdentityCreateWithCertificate(certRef cf.TypeRef, result *SecIdentityRef) error {
	status := C.SecIdentityCreateWithCertificate(nilCFTypeRef, C.SecCertificateRef(certRef), &result.Value)
	return goOSStatus(status)
}

func SecKeyCreateRandomKey(parameters *cf.DictionaryRef) (*SecKeyRef, error) {
	var cerr C.CFErrorRef
	key := C.SecKeyCreateRandomKey(C.CFDictionaryRef(parameters.Value), &cerr)
	if err := goCFErrorRef(cerr); err != nil {
		return nil, err
	}
	return &SecKeyRef{
		Value: key,
	}, nil
}

func SecKeyCopyPublicKey(key *SecKeyRef) (*SecKeyRef, error) {
	publicKey := C.SecKeyCopyPublicKey(key.Value)
	if publicKey == nilSecKey {
		return nil, ErrNotFound
	}
	return &SecKeyRef{
		Value: publicKey,
	}, nil
}

func SecKeyCopyAttributes(key *SecKeyRef) *cf.DictionaryRef {
	attr := C.SecKeyCopyAttributes(key.Value)
	return &cf.DictionaryRef{
		Value: cf.CFDictionaryRef(attr),
	}
}

func SecKeyCopyExternalRepresentation(key *SecKeyRef) (*cf.DataRef, error) {
	var cerr C.CFErrorRef
	data := C.SecKeyCopyExternalRepresentation(key.Value, &cerr)
	if err := goCFErrorRef(cerr); err != nil {
		return nil, err
	}
	return &cf.DataRef{
		Value: cf.CFDataRef(data),
	}, nil
}

func SecAccessControlCreateWithFlags(protection cf.TypeRef, flags SecAccessControlCreateFlags) (*SecAccessControlRef, error) {
	var cerr C.CFErrorRef
	access := C.SecAccessControlCreateWithFlags(C.kCFAllocatorDefault, C.CFTypeRef(protection), flags, &cerr)
	if err := goCFErrorRef(cerr); err != nil {
		return nil, err
	}
	return &SecAccessControlRef{
		ref: access,
	}, nil
}

func SecKeyCreateSignature(key *SecKeyRef, algorithm SecKeyAlgorithm, dataToSign *cf.DataRef) (*cf.DataRef, error) {
	var cerr C.CFErrorRef
	signature := C.SecKeyCreateSignature(key.Value, algorithm, C.CFDataRef(dataToSign.Value), &cerr)
	if err := goCFErrorRef(cerr); err != nil {
		return nil, err
	}
	return &cf.DataRef{
		Value: cf.CFDataRef(signature),
	}, nil
}

func SecCertificateCopyData(cert *SecCertificateRef) (*cf.DataRef, error) {
	data := C.SecCertificateCopyData(cert.Value)
	if data == nilCFData {
		return nil, ErrInvalidData
	}
	return &cf.DataRef{
		Value: cf.CFDataRef(data),
	}, nil
}

func SecCertificateCreateWithData(certData *cf.DataRef) (*SecCertificateRef, error) {
	certRef := C.SecCertificateCreateWithData(C.kCFAllocatorDefault, C.CFDataRef(certData.Value))
	if certRef == 0 {
		return nil, ErrInvalidData
	}
	return &SecCertificateRef{
		Value: certRef,
	}, nil
}

func SecIdentitySetPreferred(name *cf.StringRef, identityRef *SecIdentityRef) error {
	keyUsage := cf.NewArray([]cf.TypeRef{
		KSecAttrCanEncrypt,
		KSecAttrCanDecrypt,
		KSecAttrCanSign,
		KSecAttrCanVerify,
		KSecAttrCanWrap,
		KSecAttrCanUnwrap,
	})
	defer keyUsage.Release()

	status := C.SecIdentitySetPreferred(identityRef.Value, C.CFStringRef(name.Value), C.CFArrayRef(keyUsage.Value))
	return goOSStatus(status)
}

func SecKeyCreateWithData(keyData *cf.DataRef, attributes *cf.DictionaryRef) (*SecKeyRef, error) {
	var cerr C.CFErrorRef
	keyRef := C.SecKeyCreateWithData(C.CFDataRef(keyData.Value), C.CFDictionaryRef(attributes.Value), &cerr)
	if err := goCFErrorRef(cerr); err != nil {
		return nil, err
	}
	return &SecKeyRef{
		Value: keyRef,
	}, nil
}

func SecKeyCopyKeyExchangeResult(
	privateKey *SecKeyRef,
	algorithm SecKeyAlgorithm,
	publicKey *SecKeyRef,
	parameters *cf.DictionaryRef,
) (*cf.DataRef, error) {
	var cerr C.CFErrorRef
	dataRef := C.SecKeyCopyKeyExchangeResult(privateKey.Value, algorithm, publicKey.Value, C.CFDictionaryRef(parameters.Value), &cerr)
	if err := goCFErrorRef(cerr); err != nil {
		return nil, err
	}
	return &cf.DataRef{
		Value: cf.CFDataRef(dataRef),
	}, nil
}

func SecCopyErrorMessageString(status C.OSStatus) *cf.StringRef {
	s := C.SecCopyErrorMessageString(status, nil)
	return &cf.StringRef{
		Value: cf.CFStringRef(s),
	}
}

func GetSecAttrApplicationLabel(v *cf.DictionaryRef) []byte {
	data := C.CFDataRef(C.CFDictionaryGetValue(C.CFDictionaryRef(v.Value), unsafe.Pointer(C.kSecAttrApplicationLabel)))
	return goBytes(data)
}

func GetSecAttrApplicationTag(v *cf.DictionaryRef) string {
	data := C.CFDataRef(C.CFDictionaryGetValue(C.CFDictionaryRef(v.Value), unsafe.Pointer(C.kSecAttrApplicationTag)))
	return string(goBytes(data))
}

func GetSecAttrLabel(v *cf.DictionaryRef) string {
	ref := C.CFStringRef(C.CFDictionaryGetValue(C.CFDictionaryRef(v.Value), unsafe.Pointer(C.kSecAttrLabel)))
	return goString(ref)
}

func GetSecAttrTokenID(v *cf.DictionaryRef) string {
	ref := C.CFStringRef(C.CFDictionaryGetValue(C.CFDictionaryRef(v.Value), unsafe.Pointer(C.kSecAttrTokenID)))
	return goString(ref)
}

func GetSecAttrAccessControl(v *cf.DictionaryRef) *SecAccessControlRef {
	var keyAttributes unsafe.Pointer
	tokenID := GetSecAttrTokenID(v)
	if tokenID == "com.apple.setoken" {
		keyAttributes = C.CFDictionaryGetValue(C.CFDictionaryRef(v.Value), unsafe.Pointer(C.kSecPrivateKeyAttrs))
	} else {
		keyAttributes = C.CFDictionaryGetValue(C.CFDictionaryRef(v.Value), unsafe.Pointer(C.kSecPublicKeyAttrs))
	}
	if keyAttributes == nil {
		return nil
	}

	dv := C.CFDictionaryGetValue(C.CFDictionaryRef(keyAttributes), unsafe.Pointer(C.kSecAttrAccessControl))
	if dv == nil {
		return nil
	}

	ref := &SecAccessControlRef{
		ref: C.SecAccessControlRef(dv),
	}

	return ref
}

func GetSecValueData(v *cf.DictionaryRef) []byte {
	data := C.CFDataRef(C.CFDictionaryGetValue(C.CFDictionaryRef(v.Value), unsafe.Pointer(C.kSecValueData)))
	return goBytes(data)
}

type osStatusError struct {
	code    int
	message string
}

func (e osStatusError) Error() string {
	if e.message == "" {
		return fmt.Sprintf("OSStatus %d: unknown error", e.code)
	}
	return fmt.Sprintf("OSStatus %d: %s", e.code, e.message)
}

func goOSStatus(status C.OSStatus) error {
	switch status {
	case 0:
		return nil
	case C.errSecItemNotFound: // -25300
		return ErrNotFound
	case C.errSecDuplicateItem: // -25299
		return ErrAlreadyExists
	}

	var message string
	if ref := SecCopyErrorMessageString(status); ref.Value != 0 {
		message = goString(C.CFStringRef(ref.Value))
		defer ref.Release()
	}
	return osStatusError{
		code:    int(status),
		message: message,
	}
}

func goBytes(data C.CFDataRef) []byte {
	if data == 0 {
		return nil
	}
	return C.GoBytes(
		unsafe.Pointer(C.CFDataGetBytePtr(data)),
		C.int(C.CFDataGetLength(data)),
	)
}

func goString(ref C.CFStringRef) string {
	if ref == 0 {
		return ""
	}

	// CFStringGetCStringPtr either returns the requested pointer immediately,
	// with no memory allocations and no copying, in constant time, or returns
	// NULL.
	if cstr := C.CFStringGetCStringPtr(ref, C.kCFStringEncodingUTF8); cstr != nil {
		return C.GoString(cstr)
	}

	// The documentation recommends using CFStringGetCString if the previous one
	// fails.
	length := C.CFStringGetLength(ref)
	buf := (*C.char)(C.malloc(C.size_t(length) + 1))
	defer C.free(unsafe.Pointer(buf))

	if C.CFStringGetCString(ref, buf, length+1, C.kCFStringEncodingUTF8) == 0 {
		return ""
	}

	return C.GoString(buf)
}

type cfError struct {
	code    int
	message string
}

func (e cfError) Error() string {
	if e.message == "" {
		return fmt.Sprintf("CFError %d: unknown error", e.code)
	}
	return fmt.Sprintf("CFError %d: %s", e.code, e.message)
}

func goCFErrorRef(ref C.CFErrorRef) error {
	if ref == 0 {
		return nil
	}
	var message string
	if desc := C.CFErrorCopyDescription(ref); desc != nilCFString {
		defer C.CFRelease(C.CFTypeRef(desc))
		if cstr := C.CFStringGetCStringPtr(desc, C.kCFStringEncodingUTF8); cstr != nil {
			message = C.GoString(cstr)
		}
	}
	return &cfError{
		code:    int(C.CFErrorGetCode(ref)),
		message: message,
	}
}

func parseECDSAPublicKey(raw []byte) (crypto.PublicKey, error) {
	switch len(raw) / 2 {
	case 32: // 65 bytes
		key, err := ecdh.P256().NewPublicKey(raw)
		if err != nil {
			return nil, err
		}
		return ecdhToECDSAPublicKey(key)
	case 48: // 97 bytes
		key, err := ecdh.P384().NewPublicKey(raw)
		if err != nil {
			return nil, err
		}
		return ecdhToECDSAPublicKey(key)
	case 66: // 133 bytes:
		key, err := ecdh.P521().NewPublicKey(raw)
		if err != nil {
			return nil, err
		}
		return ecdhToECDSAPublicKey(key)
	default:
		return nil, fmt.Errorf("unsupported ECDSA key with %d bytes", len(raw))
	}
}

func parseECDSAPrivateKey(raw []byte) (crypto.PublicKey, error) {
	switch len(raw) / 3 {
	case 32: // 97 bytes
		key, err := ecdh.P256().NewPrivateKey(raw[65:])
		if err != nil {
			return nil, err
		}
		return ecdhToECDSAPublicKey(key.PublicKey())
	case 48: // 145 bytes
		key, err := ecdh.P384().NewPrivateKey(raw[97:])
		if err != nil {
			return nil, err
		}
		return ecdhToECDSAPublicKey(key.PublicKey())
	case 66: // 199 bytes:
		key, err := ecdh.P521().NewPrivateKey(raw[133:])
		if err != nil {
			return nil, err
		}
		return ecdhToECDSAPublicKey(key.PublicKey())
	default:
		return nil, fmt.Errorf("unsupported ECDSA key with %d bytes", len(raw))
	}
}

func ecdhToECDSAPublicKey(key *ecdh.PublicKey) (*ecdsa.PublicKey, error) {
	rawKey := key.Bytes()
	switch key.Curve() {
	case ecdh.P256():
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     big.NewInt(0).SetBytes(rawKey[1:33]),
			Y:     big.NewInt(0).SetBytes(rawKey[33:]),
		}, nil
	case ecdh.P384():
		return &ecdsa.PublicKey{
			Curve: elliptic.P384(),
			X:     big.NewInt(0).SetBytes(rawKey[1:49]),
			Y:     big.NewInt(0).SetBytes(rawKey[49:]),
		}, nil
	case ecdh.P521():
		return &ecdsa.PublicKey{
			Curve: elliptic.P521(),
			X:     big.NewInt(0).SetBytes(rawKey[1:67]),
			Y:     big.NewInt(0).SetBytes(rawKey[67:]),
		}, nil
	default:
		return nil, errors.New("failed to convert *ecdh.PublicKey to *ecdsa.PublicKey")
	}
}

// getSecKeyAlgorithm returns the appropriate SecKeyAlgorithm for the given key
// and options.
func getSecKeyAlgorithm(pub crypto.PublicKey, opts crypto.SignerOpts) (SecKeyAlgorithm, error) {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return KSecKeyAlgorithmECDSASignatureDigestX962, nil
	case *rsa.PublicKey:
		size := opts.HashFunc().Size()
		// RSA-PSS
		if _, ok := opts.(*rsa.PSSOptions); ok {
			switch size {
			case 32: // SHA256
				return KSecKeyAlgorithmRSASignatureDigestPSSSHA256, nil
			case 48: // SHA384
				return KSecKeyAlgorithmRSASignatureDigestPSSSHA384, nil
			case 64: // SHA512
				return KSecKeyAlgorithmRSASignatureDigestPSSSHA512, nil
			default:
				return 0, fmt.Errorf("unsupported hash function %s", opts.HashFunc().String())
			}
		}
		// RSA PKCS#1
		switch size {
		case 32: // SHA256
			return KSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256, nil
		case 48: // SHA384
			return KSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384, nil
		case 64: // SHA512
			return KSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512, nil
		default:
			return 0, fmt.Errorf("unsupported hash function %s", opts.HashFunc().String())
		}
	default:
		return 0, fmt.Errorf("unsupported key type %T", pub)
	}
}
