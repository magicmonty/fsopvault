namespace OPVault

module BinaryParser =
  open System.IO

  type ParseResult<'a> =
    | Success of 'a * BinaryReader
    | Failure of int64 * string

  type BinParser<'a> =
    | BinParser of (BinaryReader -> ParseResult<'a>)   
    
    with member this.Function = match this with BinParser pFunc -> pFunc                 

  let IOExceptionHandlingWrapper(f:BinaryReader -> ParseResult<'a>) =
    fun i -> try 
               f(i)
             with
               (e & :? IOException ) -> Failure(i.BaseStream.Position,e.Message)

      
  let Take count = BinParser(IOExceptionHandlingWrapper(fun (i:BinaryReader) -> Success(i.ReadBytes(count), i)))
  let RByte = BinParser(IOExceptionHandlingWrapper(fun (i:BinaryReader) -> Success(i.ReadByte(), i)))
  let RShort = BinParser(IOExceptionHandlingWrapper(fun (i:BinaryReader) -> Success(i.ReadInt16(), i)))
  let RInt = BinParser(IOExceptionHandlingWrapper(fun (i:BinaryReader) -> Success(i.ReadInt32(), i)))
  let RLong = BinParser(IOExceptionHandlingWrapper(fun (i:BinaryReader) -> Success(i.ReadInt64(), i)))
  let RUnsignedShort = BinParser(IOExceptionHandlingWrapper(fun (i:BinaryReader) -> Success(i.ReadUInt16(), i)))
  let RUnsignedInt = BinParser(IOExceptionHandlingWrapper(fun (i:BinaryReader) -> Success(i.ReadUInt32(), i)))
  let RUnsignedLong = BinParser(IOExceptionHandlingWrapper(fun (i:BinaryReader) -> Success(i.ReadUInt64(), i)))
  let AByte (b: byte) =
    BinParser(
      IOExceptionHandlingWrapper(
        fun (i: BinaryReader) ->
          let rB = i.ReadByte() in
            if (rB = b) 
            then Success(rB, i)
            else Failure(i.BaseStream.Position, (sprintf "Expecting %A got %A" b rB))))

  let ATag (value: string) = 
    BinParser(
      IOExceptionHandlingWrapper(
        fun (i: BinaryReader) ->
          let tag = i.ReadBytes (value |> String.length) |> Array.map char |> Array.fold (sprintf "%s%c") "" in
            if (value = tag)
            then Success(tag, i)
            else Failure(i.BaseStream.Position, (sprintf "Expecting %s got %s" value tag))))

  let ParsingStep (func:'a -> BinParser<'b>) (accumulatedResult:ParseResult<'b list>) currentSeqItem =
    match accumulatedResult with
    | Success(result,inp) ->
        match ((func currentSeqItem).Function inp) with
        | Success(result2,inp2) -> Success(result2::result,inp2)
        | Failure(offset,description) -> Failure(offset,description)
    | Failure(offset,description) -> Failure(offset,description) 

   
  let FixedSequence (s:seq<'b>,parser:BinParser<'a>) =
    BinParser(fun i ->
      match  (Seq.fold (ParsingStep (fun _ -> parser)) (Success([],i)) s) with
      | Success(result,input) -> Success(List.rev(result),input)
      | Failure(offset,description) -> Failure(offset,description))

  type BinParserBuilder() =
    member __.Bind(p:BinParser<'a>,rest:'a -> BinParser<'b>) : BinParser<'b> =
      BinParser(
        fun i -> match p.Function(i) with
                 | Success(r:'a,i2) -> ((rest r).Function i2) 
                 | Failure(offset,description) -> Failure(offset,description))
    
    member __.Return(x) = BinParser(fun i -> Success(x,i))


  let parseBinary = BinParserBuilder ()