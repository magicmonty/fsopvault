namespace Pagansoft.OPVault

module BinaryParser =
  open System.IO

  type BinParser<'a> = BinParser of (BinaryReader -> Result<'a * BinaryReader, OPVaultError>)
    with member this.Parse = match this with BinParser pFunc -> pFunc

  let private parserError (binaryReader: BinaryReader) message = 
    (binaryReader.BaseStream.Position, message) 
    |> BinaryParserError 
    |> ParserError 
    |> Error

  let IOExceptionHandlingWrapper(f:BinaryReader -> Result<'a * BinaryReader, OPVaultError>) =
    fun i -> 
      try
        f(i)
      with
        (e & :? IOException ) -> parserError i e.Message

      
  let Take count = BinParser(IOExceptionHandlingWrapper(fun (i:BinaryReader) -> Ok (i.ReadBytes(count), i)))
  let RUnsignedLong = BinParser(IOExceptionHandlingWrapper(fun (i:BinaryReader) -> Ok (i.ReadUInt64(), i)))

  let EOF = 
    BinParser(
      IOExceptionHandlingWrapper(
        fun (i:BinaryReader) ->
          try
            match i.PeekChar () with
            | v when v < 0 -> Ok ((), i)
            | v -> parserError i  (sprintf "Should be EOF but was %i!" v)
          with 
          | :? System.IO.IOException -> Ok ((), i)
          | e -> parserError i e.Message)) 

  let ATag (value: string) = 
    BinParser(
      IOExceptionHandlingWrapper(
        fun (i: BinaryReader) ->
          let tag = i.ReadBytes (value |> String.length) |> Array.map char |> Array.fold (sprintf "%s%c") "" in
            if (value = tag)
            then Ok (tag, i)
            else parserError i (sprintf "Expecting %s got %s" value tag)))

  type BinParserBuilder() =
    member __.Bind(p:BinParser<'a>,rest:'a -> BinParser<'b>) : BinParser<'b> =
      BinParser(
        fun i -> match p.Parse(i) with
                 | Ok (r: 'a, i2) -> ((rest r).Parse i2) 
                 | Error e -> Error e)
    
    member __.Return(x) = BinParser(fun i -> Ok (x, i))


  let parseBinary = BinParserBuilder ()