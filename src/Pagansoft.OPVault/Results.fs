namespace FSharp.Results

[<RequireQualifiedAccess>]
module Result =

  let combine (a: Result<'a list, 'e>) (b: Result<'a, 'e>): Result<'a list, 'e> =
    match a, b with
    | Error a, _ -> Error a
    | _, Error b -> Error b
    | Ok a, Ok b -> List.append a [ b ] |> Ok

  let fold (a: Result<'a, 'e> list): Result<'a list, 'e> =
    a |> List.fold combine (Ok [])

  let defaultValue (defaultValue: 'a) (a: Result<'a, 'e>) =
    match a with
    | Ok a -> a
    | _ -> defaultValue


[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module Results = 
  open FSharp.Core

  type ResultBuilder() = 
    // in https://github.com/jack-pappas/ExtCore/blob/master/ExtCore/Control.fs#L872 a Ok result is used
    // see also: https://fsharpforfunandprofit.com/posts/computation-expressions-builder-part1/
    member __.Zero() : Result<unit, unit> = Ok()
    member __.Bind(m, f) = Result.bind f m
    member __.Return(v) = Ok v
    
    // see https://github.com/jack-pappas/ExtCore/blob/master/ExtCore/Control.fs#L861
    /// Error operation. Similar to the Return method ('return'), but used for returning an error value.
    [<CustomOperation("error")>]
    member __.Error value : Result<'T, 'TError> = Error value
    
    member __.ReturnFrom(v) : Result<'T, 'TError> = v
    member __.Delay(f : unit -> Result<'T, 'TError>) =  f
    member __.Run(f) = f()
    
    member __.TryWith(body : unit -> Result<'T, _>, handler) = 
      try 
        body()
      with ex -> handler ex
    
    member __.TryFinally(body, handler) = 
      try 
        body()
      finally
        handler()
    
    // https://github.com/jack-pappas/ExtCore/blob/master/ExtCore/Control.fs#L917
    member __.Using(resource : 'T when 'T :> System.IDisposable, body : _ -> Result<_, _>) : Result<'U, 'TError> = 
      try 
        body resource
      finally
        if not <| isNull (box resource) then resource.Dispose()
    
    //
    member __.Combine(a : Result<'a, 'e>, b : Result<'b, 'e>) : Result<'a * 'b, 'e> = 
      match a, b with
      | Error err, _ -> Error err
      | _, Error err -> Error err
      | Ok a1, Ok b2 -> Ok(a1, b2)
    
    member __.Combine(a : Result<'a, 'e>, b : Result<'a, 'e>) : Result<'a list, 'e> = 
      match a, b with
      | Error err, _ -> Error err
      | _, Error err -> Error err
      | Ok a1, Ok b2 -> Ok [a1; b2]
    
    member __.Combine(a : Result<'a list, 'e>, b : Result<'a, 'e>) : Result<'a list, 'e> = 
      match a, b with
      | Error err, _ -> Error err
      | _, Error err -> Error err
      | Ok a, Ok b -> Ok (List.append a [ b ])
    
    member __.Combine(a : Result<'a, 'e>, b : Result<'a list, 'e>) : Result<'a list, 'e> = 
      match a, b with
      | Error err, _ -> Error err
      | _, Error err -> Error err
      | Ok a, Ok b -> Ok (a :: b)
    
    member __.Combine(a : Result<unit, 'e>, b : Result<'b, 'e>) : Result<'b, 'e> = 
      match a, b with
      | Error err, _ -> Error err
      | _, Error err -> Error err
      | Ok(), Ok b1 -> Ok b1
    
    member __.Combine(a : Result<'a, 'e>, b : Result<unit, 'e>) : Result<'a, 'e> = 
      match a, b with
      | Error err, _ -> Error err
      | _, Error err -> Error err
      | Ok a1, Ok() -> Ok a1
    
    member __.Yield x = Ok x
    member __.YieldFrom(x : Result<'a, 'b>) = x
  
  let trial = ResultBuilder()