/** @file
  GUID for UEFI WIN_CERTIFICATE structure.

  Copyright (c) 2006 - 2012, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

  @par Revision Reference:
  GUID defined in UEFI 2.0 spec.
**/

#ifndef EFI_WIN_CERTIFICATE_H__
#define EFI_WIN_CERTIFICATE_H__

//
// _WIN_CERTIFICATE.wCertificateType
//
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA  0x0002
#define WIN_CERT_TYPE_EFI_PKCS115       0x0EF0
#define WIN_CERT_TYPE_EFI_GUID          0x0EF1

///
/// The WIN_CERTIFICATE structure is part of the PE/COFF specification.
///
typedef struct {
  ///
  /// The length of the entire certificate,
  /// including the length of the header, in bytes.
  ///
  UINT32    dwLength;
  ///
  /// The revision level of the WIN_CERTIFICATE
  /// structure. The current revision level is 0x0200.
  ///
  UINT16    wRevision;
  ///
  /// The certificate type. See WIN_CERT_TYPE_xxx for the UEFI
  /// certificate types. The UEFI specification reserves the range of
  /// certificate type values from 0x0EF0 to 0x0EFF.
  ///
  UINT16    wCertificateType;
  ///
  /// The following is the actual certificate. The format of
  /// the certificate depends on wCertificateType.
  ///
  /// UINT8 bCertificate[ANYSIZE_ARRAY];
  ///
} WIN_CERTIFICATE;

#endif
