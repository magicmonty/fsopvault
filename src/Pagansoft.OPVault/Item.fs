namespace Pagansoft.OPVault

open System
open Newtonsoft.Json

type FullAddress = { City: string
                     Zip: string
                     State: string
                     Country: string
                     Street: string }


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
  | MonthYear of uint16 * uint16
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


module JSON =
  open Newtonsoft
  open Newtonsoft.Json
  open Newtonsoft.Json.Linq

  type FullAddressDTO = { City: string
                          Zip: string
                          State: string
                          Country: string
                          Street: string }

  type FieldValueDTO = 
    | StringValue of string
    | IntValue of int
    | AddressValue of FullAddressDTO

  type ShortFieldDTO = { k: string
                         v: FieldValueDTO
                         n: string
                         t: string
                         a: (string * string) array }

  type LongFieldDTO = { Type: string
                        Value: string
                        Designation: string
                        Name: string }

  type FieldDTO = 
    | Short of ShortFieldDTO
    | Long of LongFieldDTO

  type FieldConverter () =
    inherit JsonConverter<FieldDTO>() with
    override this.ReadJson(reader, objectType, existingValue, hasExistingValue, serializer) =
      base.ReadJson(reader, objectType, existingValue, hasExistingValue, serializer)

    override this.WriteJson(writer, value, serializer) =
      base.WriteJson(writer, value, serializer)

  type SectionDTO = { name: string
                      title: string
                      fields: FieldDTO array }

  type HTMLFormDTO = { htmlAction: string
                       htmlName: string
                       htmlMethod: string
                       htmlID: string }

  type PasswordHistoryEntryDTO = { Value: string 
                                   Time: Nullable<int> }

  type ItemDTO = { sections: SectionDTO array
                   fields: JObject array
                   notesPlain: string
                   htmlForm: HTMLFormDTO
                   passwordHistory: PasswordHistoryEntryDTO array }

                  static member Deserialize json = 
                    JsonConvert.DeserializeObject<ItemDTO> json