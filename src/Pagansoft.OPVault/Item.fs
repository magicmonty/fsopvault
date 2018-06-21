namespace Pagansoft.OPVault

open System
open Newtonsoft.Json
open System.ComponentModel

type FullAddress = { City: string option
                     Zip: string option
                     State: string option
                     Country: string option
                     Street: string option }

type Address = 
  | FullAddress of FullAddress
  | SimpleAddress of string

type FieldValueShort = 
  (* string *)
  | String of string
  (* address *)
  | Address of Address
  (* phone *)
  | Phone of string
  (* date *)
  | Date of DateTime
  (* gender *)
  | Gender of string
  (* monthYear *)
  | MonthYear of string * string
  (* menu *)
  | Menu of string
  (* concealed *)
  | Concealed of string
  (* cctype *)
  | CreditCardType of string 
  (* URL *)
  | URL of string 

type FieldValueLong = 
  | Password of string
  | Text of string
  | Email of string
  | Number of int
  | Radio
  | Telephone of string
  | Checkbox
  | URL of string

type FieldValue =
  | FieldValueShort of FieldValueShort
  | FieldValueLong of FieldValueLong

type Field = { Name: string
               Value: FieldValue option
               Title: string
               AdditionalInfo: Map<string, string>
               Designation: Designation }

type Section = { Name: string
                 Title: string
                 Fields: Field list }

type HTMLForm = { HtmlAction: string option
                  HtmlName: string option
                  HtmlMethod: string
                  HtmlID: string option }

type PasswordHistoryEntry = { Value: string 
                              Time: DateTime }

type Item = { Sections: Section list
              Fields: Field list
              NotesPlain: string option
              HTMLForm: HTMLForm option
              PasswordHistory: PasswordHistoryEntry list }


[<RequireQualifiedAccess>]
module Item =
  module JSON =
    open Newtonsoft
    open Newtonsoft.Json.Linq

    type FullAddressDTO = { city: string
                            zip: string
                            state: string
                            country: string
                            street: string }
                          
                          member this.ToDomainObject : FullAddress =
                            { City = this.city |> Option.fromNullableString
                              Zip = this.zip |> Option.fromNullableString
                              State = this.state |> Option.fromNullableString
                              Country = this.country |> Option.fromNullableString
                              Street = this.street |> Option.fromNullableString }

    type FieldValueDTO = 
      | StringValue of string
      | IntValue of int
      | AddressValue of FullAddressDTO

    type ShortFieldDTO = { k: string
                           v: FieldValueDTO option
                           n: string
                           t: string
                           a: Map<string, string> }
                         
                          member this.ToDomainObject =
                            let n = this.n |> Option.fromNullableString |> Option.defaultValue ""
                            let value = 
                              match this.v with
                              | Some (AddressValue address) -> address.ToDomainObject |> FullAddress |> Address |> FieldValueShort |> Some
                              | Some (IntValue i) -> i |> DateTime.fromUnixTimeStamp |> Date |> FieldValueShort |> Some
                              | Some (StringValue v) ->
                                  match n with
                                  | "phone" -> v |> Phone |> FieldValueShort |> Some
                                  | "address" ->  v |> SimpleAddress |> Address |> FieldValueShort |> Some
                                  | "date" -> DateTime.MinValue |> Date |> FieldValueShort |> Some
                                  | "gender" -> v |> Gender |> FieldValueShort |> Some
                                  | "monthYear" -> match v with
                                                   | v when v.Length = 4 ->
                                                      let month = v.Substring(0, 2)
                                                      let year = v.Substring(2, 2)
                                                      (month, year) |> MonthYear |> FieldValueShort |> Some
                                                   | _ -> None
                                  | "menu" -> v |> Menu |> FieldValueShort |> Some 
                                  | "concealed" ->  v |> Concealed |> FieldValueShort |> Some
                                  | "cctype" -> v |> CreditCardType |> FieldValueShort |> Some
                                  | "URL" -> v |> FieldValueShort.URL |> FieldValueShort |> Some
                                  | _ -> v |> String |> FieldValueShort |> Some
                               | None -> None

                            { Name = n
                              Value = value
                              Title = this.t |> Option.fromNullableString |> Option.defaultValue ""
                              AdditionalInfo = this.a
                              Designation = Designation.NoDesignation }

    type LongFieldDTO = { Type: string
                          Value: string
                          Designation: string
                          Name: string }
                        
                        member this.ToDomainObject =
                          let value = 
                            match this.Type |> FieldType.fromCode with
                            | Some FieldType.Password -> this.Value |> Password |> FieldValueLong |> Some
                            | Some FieldType.Text -> this.Value |> Text |> FieldValueLong |> Some
                            | Some FieldType.Email -> this.Value |> Email |> FieldValueLong |> Some
                            | Some FieldType.Number ->
                                match this.Value |> Int32.TryParse with
                                | true, v -> v |> Number |> FieldValueLong |> Some
                                | false, _ -> None
                            | Some FieldType.Radio -> Radio |> FieldValueLong |> Some
                            | Some FieldType.Telephone -> this.Value |> Telephone |> FieldValueLong |> Some
                            | Some FieldType.Checkbox -> Checkbox |> FieldValueLong |> Some
                            | Some FieldType.URL -> this.Value |> URL |> FieldValueLong |> Some
                            | None -> None

                          { Name = this.Name 
                            Title = this.Name
                            Value = value
                            AdditionalInfo = Map.empty
                            Designation = this.Designation |> Designation.fromCode }

    type FieldDTO = 
      | Short of ShortFieldDTO
      | Long of LongFieldDTO

      member this.ToDomainObject =
        match this with
        | Short dto -> dto.ToDomainObject
        | Long dto -> dto.ToDomainObject

    type FieldConverter() =
      inherit Newtonsoft.Json.Converters.CustomCreationConverter<FieldDTO>() with
        override __.Create(_: Type): FieldDTO =  invalidOp "not implemented"
        
        member __.Create(_: Type, jObject: JObject): FieldDTO = 
          if jObject.ContainsKey("k")
          then
            let k = jObject |> Json.tryGetString "k" |> Option.defaultValue "string" 
            let v = 
              if jObject.ContainsKey "v"
              then
                match k with
                | "date" -> jObject |> Json.tryGetInt "v" |> Option.defaultValue 0 |> IntValue |> Some
                | "address" -> jObject |> Json.tryGetString "v" |> Option.defaultValue "" |> JsonConvert.DeserializeObject<FullAddressDTO> |> AddressValue |> Some
                | _ -> jObject |> Json.tryGetString "v" |> Option.defaultValue "" |> StringValue |> Some
              else None
            
            let a = match jObject |> Json.tryGetString "a" with
                    | None -> Map.empty
                    | Some a -> a |> JsonConvert.DeserializeObject<Map<string, string>>
            Short { k = k
                    v = v
                    n = jObject |> Json.tryGetString "n" |> Option.defaultValue "" 
                    t = jObject |> Json.tryGetString "t" |> Option.defaultValue ""
                    a = a }

              
          else 
            Long { Type = jObject |> Json.tryGetString "type" |> Option.defaultValue ""
                   Value = jObject |> Json.tryGetString "value" |> Option.defaultValue ""
                   Designation = jObject |> Json.tryGetString "designation" |> Option.defaultValue ""
                   Name = jObject |> Json.tryGetString "name" |> Option.defaultValue "" }

        override this.ReadJson(reader, objectType, existingValue, serializer) = 
          let jObject = JObject.Load reader
          this.Create(objectType, jObject) :> obj

    type SectionDTO = { name: string
                        title: string
                        fields: FieldDTO array }

                      member this.ToDomainObject =
                        { Name = this.name |> Option.fromNullableString |> Option.defaultValue "" 
                          Title = this.title |> Option.fromNullableString |> Option.defaultValue ""
                          Fields = this.fields |> Array.fromNullable |> Array.map (fun f -> f.ToDomainObject) |> Array.toList }

    type HTMLFormDTO = { htmlAction: string
                         htmlName: string
                         htmlMethod: string
                         htmlID: string }

                       member this.ToDomainObject =
                        { HtmlAction = this.htmlAction |> Option.fromNullableString
                          HtmlName = this.htmlName |> Option.fromNullableString
                          HtmlMethod = this.htmlMethod |> Option.fromNullableString |> Option.defaultValue ""
                          HtmlID = this.htmlID |> Option.fromNullableString }

    type PasswordHistoryEntryDTO = { Value: string 
                                     Time: Nullable<int> }

                                   member this.ToDomainObject : PasswordHistoryEntry =
                                    { Value = this.Value |> Option.fromNullableString |> Option.defaultValue ""
                                      Time = this.Time |> Option.fromNullable |> Option.defaultValue 0 |> DateTime.fromUnixTimeStamp }

    type ItemDTO = { sections: SectionDTO array
                     fields: FieldDTO array
                     notesPlain: string
                     htmlForm: HTMLFormDTO
                     passwordHistory: PasswordHistoryEntryDTO array }
                    
                    member this.ToDomainObject =
                      { Sections = this.sections |> Array.fromNullable |> Array.map (fun s -> s.ToDomainObject) |> Array.toList
                        Fields = this.fields |> Array.fromNullable |> Array.map (fun s -> s.ToDomainObject) |> Array.toList
                        NotesPlain = this.notesPlain |> Option.fromNullableString
                        HTMLForm = 
                          try
                            this.htmlForm.ToDomainObject |> Some
                          with
                            | _ -> None
                        PasswordHistory = this.passwordHistory  |> Array.fromNullable |> Array.map (fun s -> s.ToDomainObject) |> Array.toList }

                    static member Deserialize json = 
                      try
                        let fieldConverter = FieldConverter()
                        JsonConvert.DeserializeObject<ItemDTO> (json, fieldConverter)
                        |> fun dto -> dto.ToDomainObject
                        |> Ok
                      with
                        | ex -> ex.Message |> JSONParserError |> ParserError |> Error

  let deserialize json = JSON.ItemDTO.Deserialize json
