#load @"../.paket/load/netstandard2.0/Microsoft.AspNetCore.Cryptography.KeyDerivation.fsx"
#load @"../.paket/load/netstandard2.0/FSharp.Data.fsx"

#load "Errors.fs"
#load "File.fs"
#load "ResultModule.fs"
#load "BinaryParser.fs"
#load "OPData.fs"
#load "Profile.fs"

open OPVault
open FSharp.Results.Result

let getOverview password (profile: Profile) (encryptedOverview: byte array) =
  trial {
    let! decryptedProfile = profile |> Profile.decrypt password
    let! overviewKey = decryptedProfile |> Profile.getDecryptedOverviewKey
    let! encryptedOverviewData = encryptedOverview |> OPData.parseBytes
    let! decryptedOverviewData = encryptedOverviewData |> OPData.authenticateAndDecrypt overviewKey
    return! decryptedOverviewData |> OPData.getPlainText
  }

let encryptedOverview = "b3BkYXRhMDEIAAAAAAAAAMQDerODSnrtEVkZHp0tO5qokNWe+77F7yjsHcCvBEdxYL9DPSUuPV4FDv1F4E3VXWoY4BBYZrm8G3IUekJhL3E="
let password = "freddy"

trial {
  let! profile = Profile.read "testdata\\onepassword_data\\default\\profile.js"
  let encryptedOverview = encryptedOverview |> System.Convert.FromBase64String
  return! getOverview password profile encryptedOverview
}

let encryptedItemKey = "6MnmUT7fNchO0lIDNYGITOAO0cubw8Qsad1dEBZFCUSXrUOR7IkFUwddSA8QBJTH7P7iJytKB00KclFRNR/zf+AC+VD6aCQiznj1zx8uKoxG9Wv1v4YsnH95NbC8UvRxCn+XA+6WRZII2kWN10IN9w=="
