namespace OPVault

open System.Security.Cryptography
open System.IO
open System
open Errors
open FSharp.Results.Result

type EncryptedOPData = { PlainTextSize: uint64
                         PaddingSize: uint64
                         IV: byte array
                         CipherText: byte array
                         HMAC: byte array }
                         
                        member this.HashBytes : byte array =
                         Array.concat [| "opdata01".ToCharArray() |> Array.map byte
                                         System.BitConverter.GetBytes(this.PlainTextSize)
                                         this.IV
                                         this.CipherText |]
 
                        member this.Authenticate (keys: KeyPair) =
                          let calculatedHMAC = keys.Hmac this.HashBytes
                          if calculatedHMAC = this.HMAC
                          then Ok ()
                          else CouldNotAuthenticate |> OPDataError |> Error

                        member this.Decrypt (keys: KeyPair) =
                          match this.CipherText with
                          | [||] -> EmptyCipherText |> OPDataError |> Error
                          | _ ->
                            trial {
                              let! plainTextBytes = keys.DecryptToByteArray this
                              return Decrypted { Keys = keys.DeriveKeysFromDecryptedBytes plainTextBytes
                                                 PlainText = plainTextBytes }
                            }

                        member this.DecryptKeys (keys: KeyPair) =
                          match this.CipherText with
                          | [||] -> EmptyCipherText |> OPDataError |> Error
                          | _ ->
                            trial {
                              let! plainTextBytes = keys.DecryptToByteArray this
                              return keys.DeriveKeysFromDecryptedBytes plainTextBytes
                            }

and DecryptedOPData = { PlainText: byte array
                        Keys: KeyPair }

and OPData = 
  | Encrypted of EncryptedOPData
  | Decrypted of DecryptedOPData
 
  member this.PlainTextAsString() =
    match this with
    | Decrypted data -> data.PlainText |> String.bytesAsString |> Ok
    | Encrypted _ -> OPDataIsNotDecrypted |> OPDataError |> Error

  member this.Decrypt (keys: KeyPair) =
    match this with
    | Decrypted data -> Ok (Decrypted data)
    | Encrypted data -> data.Decrypt keys

  member this.DecryptKeys (keys: KeyPair) =
    match this with
    | Decrypted data -> Ok data.Keys
    | Encrypted data -> data.DecryptKeys keys

  member this.Authenticate (keys: KeyPair) =
    match this with
    | Decrypted _ -> Ok ()
    | Encrypted data -> data.Authenticate keys


and KeyPair = { EncryptionKey: byte array
                AuthenticationKey: byte array }
                 
                member this.Hmac (bytes: byte array) = 
                  use hmac = new HMACSHA256(this.AuthenticationKey)
                  hmac.ComputeHash(bytes)
                 
                member this.Cipher iv =
                    let d = System.Security.Cryptography.Aes.Create()
                    d.KeySize <- 256
                    d.Mode <- CipherMode.CBC
                    d.IV <- iv
                    d.Key <- this.EncryptionKey
                    d.Padding <- PaddingMode.None
                    d

                member __.DeriveKeysFromDecryptedBytes (plainTextBytes: byte array) =
                  let hash = 
                    use h = new SHA512Managed()
                    h.ComputeHash plainTextBytes
                    
                  { EncryptionKey = hash |> Array.take 32
                    AuthenticationKey = hash |> Array.skip 32 }

                member this.DecryptToByteArray data =
                  let isValidCipherText cipherText =
                    let cipherLength = cipherText |> Array.length
                    let calculatedCipherLength = int (data.PaddingSize + data.PlainTextSize)
                    cipherLength = calculatedCipherLength

                  match data.CipherText with
                  | [||] -> EmptyCipherText |> OPDataError |> Error
                  | cipherText when cipherText |> isValidCipherText ->
                    try
                      use decryptor = this.Cipher data.IV                  
                      use msDecrypt = new MemoryStream(cipherText)
                      use csDecrypt = new CryptoStream(msDecrypt, decryptor.CreateDecryptor(), CryptoStreamMode.Read)

                      let cipherLength = cipherText |> Array.length
                      let mutable plaintext = [| for _ in 1 .. cipherLength -> 0uy |]
                      csDecrypt.Read(plaintext, 0, int cipherLength) |> ignore
                      
                      let plaintext = plaintext |> Array.skip (int data.PaddingSize)
                      Ok plaintext
                    with
                    | _ -> CouldNotDecrypt |> OPDataError |> Error
                  | _ -> InvalidCipherText |> OPDataError |> Error
                
                member this.DecryptByteArray (bytes: byte array) =
                  match bytes with
                  | [||] -> EmptyCipherText |> OPDataError |> Error
                  | _ ->
                    try
                      let l = bytes |> Array.length
                      let iv = bytes.[0..15]
                      let hmac = bytes.[(l - 32) .. ]
                      let cipherText = bytes.[16..(l - 32 - 1)]
                      let calculatedHMAC = this.Hmac (bytes.[0..(l - 32 - 1)])
                      if hmac <> calculatedHMAC
                      then CouldNotAuthenticate |> OPDataError |> Error
                      else
                        use decryptor = this.Cipher iv
                        use msDecrypt = new MemoryStream(cipherText)
                        use csDecrypt = new CryptoStream(msDecrypt, decryptor.CreateDecryptor(), CryptoStreamMode.Read)
                        let cipherLength = cipherText |> Array.length
                        let padding = 16 - (cipherLength % 16)
                        let mutable plaintext = [| for _ in 1 .. cipherLength -> 0uy |]
                        csDecrypt.Read(plaintext, 0, int cipherLength) |> ignore
                        plaintext |> Array.skip padding |> Ok
                    with
                    | _ -> CouldNotDecrypt |> OPDataError |> Error
                
[<RequireQualifiedAccess>]
module KeyPair =
  open Microsoft.AspNetCore.Cryptography.KeyDerivation
  open BinaryParser
  
  let empty = { EncryptionKey = [||]
                AuthenticationKey = [||] }

  let private KeySize = 256 / 8 // 256 bits

  let private parse binaryReader =
    let parser = parseBinary {
      let! enc = Take KeySize
      let! auth = Take KeySize
      return { EncryptionKey = enc
               AuthenticationKey = auth }
    }

    match parser.Function binaryReader with
    | Ok (v, _) -> Ok v
    | Error e -> Error e

  let parseBytes (bytes: byte array) =
    use stream = new MemoryStream(bytes)
    use reader = new BinaryReader(stream)
    parse reader

  let deriveFromMasterPassword (password: string) salt iterations =
    KeyDerivation.Pbkdf2(password, salt, KeyDerivationPrf.HMACSHA512, iterations, KeySize * 2) |> parseBytes

[<RequireQualifiedAccess>]
module OPData =
  open BinaryParser

  let private parse binaryReader =     
    trial { 
      let parser = parseBinary {
        let! _ = ATag "opdata01"
        let! plainTextSize = RUnsignedLong
        let paddingSize = 16UL - (plainTextSize % 16UL)
        let! iv = Take 16
        let! cipherText = Take (paddingSize + plainTextSize |> int)
        let! hmac = Take (256 / 8)
        let! _ = EOF

        return Encrypted { PlainTextSize = plainTextSize
                           PaddingSize = paddingSize
                           IV = iv
                           CipherText = cipherText
                           HMAC = hmac }
      }
      let! v, _ = parser.Function binaryReader
      return v
    }

  let parseBytes (bytes: byte array) =
    use stream = new MemoryStream(bytes)
    use reader = new BinaryReader(stream)
    parse reader

  let authenticate (keys: KeyPair) (data: OPData) = 
    data.Authenticate keys

  let authenticateAndDecrypt (keys: KeyPair) (data: OPData) =
    trial {
      do! authenticate keys data
      return! data.Decrypt keys
    }

  let getPlainText (data: OPData) = data.PlainTextAsString

  let getDecryptedKeys (data: OPData) =
    match data with
    | Encrypted _ -> OPDataIsNotDecrypted |> OPDataError |> Error
    | Decrypted data -> Ok data.Keys

