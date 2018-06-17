namespace Pagansoft.OPVault

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
  open Newtonsoft.Json

  type ProfileDTO = { lastUpdatedBy: string
                      updatedAt: Nullable<int>
                      profileName: string
                      salt: string
                      masterKey: string
                      overviewKey: string
                      iterations: int
                      uuid: string
                      createdAt: int }


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

  let private convertToProfileData (dto: ProfileDTO) : EncryptedProfileData =
    { LastUpdatedBy = dto.lastUpdatedBy |> Option.fromNullableString
      UpdatedAt = dto.updatedAt |> Option.fromNullable |> Option.map DateTime.fromUnixTimeStamp
      ProfileName = dto.profileName
      Salt = dto.salt |> ByteArray.fromBase64
      MasterKey = dto.masterKey |> ByteArray.fromBase64
      OverviewKey = dto.overviewKey |> ByteArray.fromBase64
      Iterations = dto.iterations
      UUID = dto.uuid
      CreatedAt = dto.createdAt |> DateTime.fromUnixTimeStamp }

  let private parseProfileJSON (json: string) : Result<EncryptedProfileData, OPVaultError> =
    try
      JsonConvert.DeserializeObject<ProfileDTO> json
      |> convertToProfileData
      |> Ok
    with
    | e -> JSONParserError json |> ParserError |> Result.Error

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
  