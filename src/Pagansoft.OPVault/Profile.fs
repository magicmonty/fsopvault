namespace Pagansoft.OPVault

open Chiron
open System

type EncryptedProfileData = { LastUpdatedBy: string option
                              UpdatedAt: DateTime option
                              ProfileName: string
                              Salt: byte array
                              MasterKey: byte array
                              OverviewKey: byte array
                              Iterations: int
                              UUID: string
                              CreatedAt: DateTime }

                            static member FromJson (_ : EncryptedProfileData) : Json<EncryptedProfileData> =
                              json {
                                let! lastUpdatedBy = Json.tryRead "lastUpdatedBy"
                                let! (updatedAt: int option) = Json.tryRead "updatedAt"
                                let! profileName = Json.read "profileName"
                                let! salt = Json.read "salt"
                                let! masterKey = Json.read "masterKey"
                                let! overviewKey = Json.read "overviewKey"
                                let! iterations = Json.read "iterations"
                                let! uuid = Json.read "uuid"
                                let! (createdAt: int) = Json.read "createdAt"

                                return { LastUpdatedBy = lastUpdatedBy
                                         UpdatedAt = updatedAt |> Option.map DateTime.fromUnixTimeStamp
                                         ProfileName = profileName
                                         Salt = salt |> ByteArray.fromBase64
                                         MasterKey = masterKey |> ByteArray.fromBase64
                                         OverviewKey = overviewKey |> ByteArray.fromBase64
                                         Iterations = iterations
                                         UUID = uuid
                                         CreatedAt = createdAt |> DateTime.fromUnixTimeStamp }
                              }

type DecryptedProfileData = { LastUpdatedBy: string option
                              UpdatedAt: System.DateTime option
                              ProfileName: string
                              Salt: byte array
                              MasterKey: KeyPair
                              OverviewKey: KeyPair
                              Iterations: int
                              UUID: string
                              CreatedAt: System.DateTime }

type Profile = 
  | EncryptedProfile of EncryptedProfileData
  | DecryptedProfile of DecryptedProfileData

[<RequireQualifiedAccess>]
module Profile =
  open FSharp.Results.Results


  let empty = 
    { LastUpdatedBy = None
      UpdatedAt = None
      ProfileName = "default"
      Salt = [| for _ in 1 .. 16 -> 0uy |]
      MasterKey = KeyPair.empty
      OverviewKey = KeyPair.empty
      Iterations = 50000
      UUID = "00000000000000000000000000000000"
      CreatedAt = DateTime.Now }
  
  let private startMarker = "varprofile={"
  let private endMarker = "};"

  let private profileError error = error |> ProfileError |> Result.Error

  let private makeJSONText = String.makeJSON startMarker endMarker

  let private parseProfileJSON (json: string) : Result<EncryptedProfileData, OPVaultError> =
    try
      Ok (Json.parse json |> Json.deserialize)
    with
    | e -> JSONParserError e.Message |> ParserError |> Result.Error

  let read filename =
    trial {
      let! content = File.read filename
      let! content = makeJSONText content
      let! profileData = content |> parseProfileJSON
      return EncryptedProfile profileData 
    }

  let getDecryptedProfileData profile =
    match profile with
    | DecryptedProfile profileData -> Ok profileData
    | _ -> profileError ProfileIsEncrypted
    
  let getDecryptedOverviewKey profile =
    match profile with
    | EncryptedProfile _ -> profileError ProfileIsEncrypted
    | DecryptedProfile profile -> Ok profile.OverviewKey

  let getDecryptedMasterKey profile =
    match profile with
    | EncryptedProfile _ -> profileError ProfileIsEncrypted
    | DecryptedProfile profile -> Ok profile.MasterKey

  let private decryptKey getEncryptedKeyData (derivedKeys: KeyPair) (encryptedProfileData: EncryptedProfileData) = 
    trial {
      let! encryptedKeyData = encryptedProfileData |> getEncryptedKeyData |> OPData.parseBytes
      return! encryptedKeyData.DecryptKeys derivedKeys
    }

  let private decryptMasterKey = decryptKey (fun p -> p.MasterKey)
  let private decryptOverviewKey = decryptKey (fun p -> p.OverviewKey)

  let decrypt password (profile: Profile) =
    match profile with
    | DecryptedProfile _ -> Ok profile
    | EncryptedProfile encryptedProfile ->
      trial {
        let! derivedKeys = KeyPair.deriveFromMasterPassword password encryptedProfile.Salt encryptedProfile.Iterations
        let! masterKey = decryptMasterKey derivedKeys encryptedProfile
        let! overviewKey = decryptOverviewKey derivedKeys encryptedProfile

        return DecryptedProfile
          { LastUpdatedBy = encryptedProfile.LastUpdatedBy
            UpdatedAt = encryptedProfile.UpdatedAt
            ProfileName = encryptedProfile.ProfileName
            Salt = encryptedProfile.Salt
            MasterKey = masterKey
            OverviewKey = overviewKey
            Iterations = encryptedProfile.Iterations
            UUID = encryptedProfile.UUID
            CreatedAt = encryptedProfile.CreatedAt }
      }
  