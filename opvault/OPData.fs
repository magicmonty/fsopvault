namespace OPVault

#if INTERACTIVE
#load @".paket/load/netstandard2.0/Microsoft.AspNetCore.Cryptography.KeyDerivation.fsx"
#endif

open System.Security.Cryptography
open System.IO
open System

type OPData = { PlainTextSize: uint64
                PaddingSize: uint64
                IV: byte array
                CipherText: byte array
                PlainText: byte array option
                DecryptedKeys: KeyPair option
                HMAC: byte array }
 
                member this.HashBytes : byte array =
                  Array.concat [| "opdata01".ToCharArray() |> Array.map byte
                                  System.BitConverter.GetBytes(this.PlainTextSize)
                                  this.IV
                                  this.CipherText |]
 
                member this.Authenticate (keys: KeyPair) =
                  if (keys.Hmac this.HashBytes) = this.HMAC
                  then Ok (keys, this)
                  else Error "Could not authenticate"

and KeyPair = { EncryptionKey: byte array
                AuthenticationKey: byte array }
                 
                member this.Hmac (bytes: byte array) = 
                  use hmac = new HMACSHA256(this.AuthenticationKey)
                  hmac.ComputeHash(bytes)
                 
                member this.Decrypt data =
                  match data.CipherText with
                  | [||] -> Error "Cipher text is empty"
                  | _ ->
                    use decryptor = System.Security.Cryptography.Aes.Create()
                    decryptor.KeySize <- 256
                    decryptor.Mode <- CipherMode.CBC
                    decryptor.IV <- data.IV
                    decryptor.Key <- this.EncryptionKey
                    decryptor.Padding <- PaddingMode.None
                  
                    use msDecrypt = new MemoryStream(data.CipherText)
                    use csDecrypt = new CryptoStream(msDecrypt, decryptor.CreateDecryptor(), CryptoStreamMode.Read)
                    use dsDecrypt = new MemoryStream()
                    csDecrypt.CopyTo(dsDecrypt)
                    let plaintext = (dsDecrypt.GetBuffer() |> Array.skip (int data.PaddingSize) |> Array.take (int data.PlainTextSize))
                    let hash = 
                      use h = new SHA512Managed()
                      h.ComputeHash plaintext
                    
                    let keyPair = { EncryptionKey = hash |> Array.take 32
                                    AuthenticationKey = hash |> Array.skip 32 }
                    
                    Ok { data with DecryptedKeys = Some keyPair
                                   PlainText = Some plaintext }
                
module KeyPair =
  open Microsoft.AspNetCore.Cryptography.KeyDerivation
  open BinaryParser
  open System
  
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
    | Error (_, e) -> Error e

  let parseBytes (bytes: byte array) =
    use stream = new MemoryStream(bytes)
    use reader = new BinaryReader(stream)
    parse reader

  let parseBase64String data =
    Convert.FromBase64String(data) |> parseBytes

  let deriveFromMasterPassword (password: string) salt iterations =
    KeyDerivation.Pbkdf2(password, salt, KeyDerivationPrf.HMACSHA512, iterations, KeySize * 2) |> parseBytes

module OPData =
  open BinaryParser
  open System

  let empty =  { PlainTextSize = 0UL
                 PaddingSize = 0UL
                 IV = [||]
                 CipherText = [||]
                 PlainText = None
                 DecryptedKeys = None
                 HMAC = [||] }

  let private parse binaryReader = 
    let parser = parseBinary {
      let! _ = ATag "opdata01"
      let! plainTextSize = RUnsignedLong
      let paddingSize = 16UL - (plainTextSize % 16UL)
      let! iv = Take 16
      let! cipherText = Take (paddingSize + plainTextSize |> int)
      let! hmac = Take (256 / 8)
      let! _ = EOF

      return { PlainTextSize = plainTextSize
               PaddingSize = paddingSize
               IV = iv
               CipherText = cipherText
               PlainText = None
               DecryptedKeys = None
               HMAC = hmac }
    }
    
    match parser.Function binaryReader with
    | Ok (v, _) -> Ok v
    | Error (_, e) -> Error e

  let parseBytes (bytes: byte array) =
    use stream = new MemoryStream(bytes)
    use reader = new BinaryReader(stream)
    parse reader

  let parseBase64String data =
    Convert.FromBase64String(data) |> parseBytes

  let parseRawFile fileName = System.IO.File.ReadAllBytes fileName |> parseBytes

  let authenticate (keys: KeyPair) (data: OPData) = 
    data.Authenticate keys

  let authenticateRawFile (keys: KeyPair) filename =
    match parseRawFile filename with
    | Ok data -> data.Authenticate keys
    | error -> error

  let authenticateRawFileWithPassword (password: string) (salt: byte array) (iterations: int) filename =
    match KeyPair.deriveFromMasterPassword password salt iterations with
    | Ok keys -> authenticateRawFile keys filename
    | error -> error

  let authenticateAndDecrypt (keys: KeyPair) (data: OPData) =
    match authenticate keys data with
    | Ok (keys, data) -> keys.Decrypt data
    | error -> error

  let authenticateAndDecryptRawFile (keys: KeyPair) filename =
    match parseRawFile filename with
    | Ok data -> data |> authenticateAndDecrypt keys
    | error -> error

  let authenticateAndDecryptRawFileWithPassword (password: string) (salt: byte array) (iterations: int) filename =
    match KeyPair.deriveFromMasterPassword password salt iterations with
    | Ok keys -> authenticateAndDecryptRawFile keys filename
    | error -> error


module TestKeyPair =
  let profile = 
    match Profile.read "testdata\\onepassword_data\\default\\profile.js" with
    | Ok profile -> 
      match profile |> Profile.decrypt "freddy" with
      | Ok (DecryptedProfile profile) -> profile
      | _ -> Profile.empty
    | _ -> Profile.empty

  let toByteArray str =
    System.Convert.FromBase64String(str)

  let encryptedItemKey = "6MnmUT7fNchO0lIDNYGITOAO0cubw8Qsad1dEBZFCUSXrUOR7IkFUwddSA8QBJTH7P7iJytKB00KclFRNR/zf+AC+VD6aCQiznj1zx8uKoxG9Wv1v4YsnH95NbC8UvRxCn+XA+6WRZII2kWN10IN9w==" |> toByteArray
  let encryptedOverview = "b3BkYXRhMDEIAAAAAAAAAMQDerODSnrtEVkZHp0tO5qokNWe+77F7yjsHcCvBEdxYL9DPSUuPV4FDv1F4E3VXWoY4BBYZrm8G3IUekJhL3E=" |> toByteArray

  let overview = 
    match profile.OverviewKey.DecryptedKeys with
    | Some keys ->
      match encryptedOverview |> OPData.parseBytes with
      | Ok overview ->
        match overview |> OPData.authenticateAndDecrypt keys with
        | DecryptionSuccess d -> 
          printfn "%A" (d.PlainText |> Array.map char)
          DecryptionSuccess 
        | v -> v
      | _ -> AuthenticationFailed
    | None -> AuthenticationFailed
  
