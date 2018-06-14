namespace OPVault

open System
open System.Security.Cryptography
open FSharp.Data

type UID = string

type OPData1 = 
  | Encrypted of byte array
  | Decrypted of byte array

type BandJSItem = JsonProvider<""" 
  { "category": "001", 
    "created": 1325483950, 
    "d": "FOO", 
    "folder": "SomeString", 
    "hmac": "SomeString", 
    "k": "SomeString", 
    "o": "SomeString", 
    "tx": 1347560906, 
    "updated": 1325483950, 
    "uuid": "468B1E24F93B413DAD57ABE6F1C01DF6" } """>


type Profile = { UID: UID
                 ProfileName: string
                 UpdatedAt: DateTime
                 CreatedAt: DateTime
                 LastUpdatedBy: string
                 PasswordHint: string option
                 MasterKey: byte array
                 OverviewKey: byte array 
                 Salt: byte array
                 Iterations: int64 }

type ItemData = { HMAC: HMACSHA256
                  CryptoKey: byte array
                  MACKey: byte array
                  Data: OPData1
                  OverviewData: OPData1 }

type ItemManagement = { UID: UID
                        Category: Category
                        Folder: UID
                        Created: DateTime
                        TransactionTimestamp: DateTime
                        Updated: DateTime
                        LastModified: DateTime
                        IsFavorite: bool
                        IsTrashed: bool }

type FolderItem = { UID: UID 
                    Created: DateTime
                    TransactionTimestamp: DateTime
                    Updated: DateTime 
                    IsSmartFolder: bool
                    OverviewData: OPData1 }