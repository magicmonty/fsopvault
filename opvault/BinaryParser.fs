namespace OPVault

module BinaryParser =
  open System.IO

  type ParseResult<'a> = Result<'a * BinaryReader, int64 * string>

  type BinParser<'a> =
    | BinParser of (BinaryReader -> ParseResult<'a>)   
    
    with member this.Function = match this with BinParser pFunc -> pFunc                 

  let IOExceptionHandlingWrapper(f:BinaryReader -> ParseResult<'a>) =
    fun i -> try 
               f(i)
             with
               (e & :? IOException ) -> Error (i.BaseStream.Position, e.Message)

      
  let Take count = BinParser(IOExceptionHandlingWrapper(fun (i:BinaryReader) -> Ok (i.ReadBytes(count), i)))
  let RByte = BinParser(IOExceptionHandlingWrapper(fun (i:BinaryReader) -> Ok (i.ReadByte(), i)))
  let RShort = BinParser(IOExceptionHandlingWrapper(fun (i:BinaryReader) -> Ok (i.ReadInt16(), i)))
  let RInt = BinParser(IOExceptionHandlingWrapper(fun (i:BinaryReader) -> Ok (i.ReadInt32(), i)))
  let RLong = BinParser(IOExceptionHandlingWrapper(fun (i:BinaryReader) -> Ok (i.ReadInt64(), i)))
  let RUnsignedShort = BinParser(IOExceptionHandlingWrapper(fun (i:BinaryReader) -> Ok (i.ReadUInt16(), i)))
  let RUnsignedInt = BinParser(IOExceptionHandlingWrapper(fun (i:BinaryReader) -> Ok (i.ReadUInt32(), i)))
  let RUnsignedLong = BinParser(IOExceptionHandlingWrapper(fun (i:BinaryReader) -> Ok (i.ReadUInt64(), i)))
  let EOF = 
    BinParser(
      IOExceptionHandlingWrapper(
        fun (i:BinaryReader) ->
          try
            match i.PeekChar () with
            | v when v < 0 -> Ok ((), i)
            | v -> Error (i.BaseStream.Position, (sprintf "Should be EOF but was %i!" v))
          with 
          | :? System.IO.IOException -> Ok ((), i)
          | e -> Error (i.BaseStream.Position, e.Message))) 

  let AByte (b: byte) =
    BinParser(
      IOExceptionHandlingWrapper(
        fun (i: BinaryReader) ->
          let rB = i.ReadByte() in
            if (rB = b) 
            then Ok (rB, i)
            else Error (i.BaseStream.Position, (sprintf "Expecting %A got %A" b rB))))

  let ATag (value: string) = 
    BinParser(
      IOExceptionHandlingWrapper(
        fun (i: BinaryReader) ->
          let tag = i.ReadBytes (value |> String.length) |> Array.map char |> Array.fold (sprintf "%s%c") "" in
            if (value = tag)
            then Ok (tag, i)
            else Error (i.BaseStream.Position, (sprintf "Expecting %s got %s" value tag))))

  let ParsingStep (func:'a -> BinParser<'b>) (accumulatedResult:ParseResult<'b list>) currentSeqItem =
    match accumulatedResult with
    | Ok (result, inp) ->
        match ((func currentSeqItem).Function inp) with
        | Ok (result2, inp2) -> Ok (result2::result, inp2)
        | Error e -> Error e
    | Error e -> Error e

  let FixedSequence (s:seq<'b>, parser:BinParser<'a>) =
    BinParser(fun i ->
      match  (Seq.fold (ParsingStep (fun _ -> parser)) (Ok ([], i)) s) with
      | Ok (result, input) -> Ok(List.rev(result), input)
      | Error e -> Error e)

  type BinParserBuilder() =
    member __.Bind(p:BinParser<'a>,rest:'a -> BinParser<'b>) : BinParser<'b> =
      BinParser(
        fun i -> match p.Function(i) with
                 | Ok (r: 'a, i2) -> ((rest r).Function i2) 
                 | Error e -> Error e)
    
    member __.Return(x) = BinParser(fun i -> Ok (x, i))


  let parseBinary = BinParserBuilder ()