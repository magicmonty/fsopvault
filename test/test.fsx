#load @"../.paket/load/Microsoft.AspNetCore.Cryptography.KeyDerivation.fsx"
#load @"../.paket/load/Newtonsoft.Json.fsx"

#load "../src/Pagansoft.OPVault/Types.fs"
#load "../src/Pagansoft.OPVault/Designation.fs"
#load "../src/Pagansoft.OPVault/FieldType.fs"
#load "../src/Pagansoft.OPVault/Crypto.fs"
#load "../src/Pagansoft.OPVault/Helpers.fs"
#load "../src/Pagansoft.OPVault/Results.fs"
#load "../src/Pagansoft.OPVault/BinaryParser.fs"
#load "../src/Pagansoft.OPVault/OPData.fs"
#load "../src/Pagansoft.OPVault/Overview.fs"
#load "../src/Pagansoft.OPVault/Category.fs"
#load "../src/Pagansoft.OPVault/Profile.fs"
#load "../src/Pagansoft.OPVault/Folder.fs"
#load "../src/Pagansoft.OPVault/Item.fs"
#load "../src/Pagansoft.OPVault/BandFile.fs"
#load "../src/Pagansoft.OPVault/Vault.fs"

open Pagansoft.OPVault
open FSharp.Results
open FSharp.Results.Results
open ResultOperators
open Newtonsoft
open Newtonsoft.Json
open Newtonsoft.Json.Linq
open System.IO

let password = "freddy"
let vaultDir = "test/testdata/default"
let vault =  LockedVault { VaultDir = vaultDir }

let items = 
  trial {
    let! unlocked = vault |> Vault.unlock password
    return! unlocked 
            |> Vault.getKeysByTitle "Company's FTP"
  } 
  |> Result.defaultValue []
 
let item = 
  trial {
    let! unlocked = vault |> Vault.unlock password
    return! unlocked 
            |> Vault.getItemByUUID (UUID "4E36C011EE8348B1B24418218B04018C")
  }