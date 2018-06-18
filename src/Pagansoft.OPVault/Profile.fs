namespace Pagansoft.OPVault

open System
open FSharp.Results

type EncryptedProfileData = { LastUpdatedBy: string option
                              UpdatedAt: DateTime option
                              ProfileName: string
                              Salt: byte array
                              MasterKey: byte array
                              OverviewKey: byte array
                              Iterations: int
                              UUID: string
                              CreatedAt: DateTime }

and ProfileDTO = { lastUpdatedBy: string
                   updatedAt: Nullable<int>
                   profileName: string
                   salt: string
                   masterKey: string
                   overviewKey: string
                   iterations: int
                   uuid: string
                   createdAt: int }

                 member this.ToDomainObject : EncryptedProfileData =
                     { LastUpdatedBy = this.lastUpdatedBy |> Option.fromNullableString
                       UpdatedAt = this.updatedAt |> Option.fromNullable |> Option.map DateTime.fromUnixTimeStamp
                       ProfileName = this.profileName
                       Salt = this.salt |> ByteArray.fromBase64
                       MasterKey = this.masterKey |> ByteArray.fromBase64
                       OverviewKey = this.overviewKey |> ByteArray.fromBase64
                       Iterations = this.iterations
                       UUID = this.uuid
                       CreatedAt = this.createdAt |> DateTime.fromUnixTimeStamp }


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
  open ResultOperators

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
  
  let private profileError error = error |> ProfileError |> Result.Error
  
  module JSON =
    let clean = String.makeJSON "varprofile={" "};"

    let deserialzeDTO = Json.deserialize<ProfileDTO>

    let parse (json: string) : Result<EncryptedProfileData, OPVaultError> =
      json
      |> deserialzeDTO
      |=> fun dto -> dto.ToDomainObject

  let read filename =
    File.read filename
    |> Result.bind JSON.clean
    |> Result.bind JSON.parse
    |> Result.map EncryptedProfile

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
    encryptedProfileData 
    |> getEncryptedKeyData 
    |> OPData.parseBytes
    |-> fun data -> data.DecryptKeys derivedKeys

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
  