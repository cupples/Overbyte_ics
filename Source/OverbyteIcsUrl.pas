{*_* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *

Author:       Fran?ois PIETTE
Creation:     Aug 08, 2004 (extracted from various ICS components)
Version:      8.65
Description:  This unit contain support routines for URL handling.
EMail:        francois.piette@overbyte.be         http://www.overbyte.be
Support:      https://en.delphipraxis.net/forum/37-ics-internet-component-suite/
Legal issues: Copyright (C) 1997-2020 by Fran?ois PIETTE
              Rue de Grady 24, 4053 Embourg, Belgium.
              <francois.piette@overbyte.be>

              This software is provided 'as-is', without any express or
              implied warranty.  In no event will the author be held liable
              for any  damages arising from the use of this software.

              Permission is granted to anyone to use this software for any
              purpose, including commercial applications, and to alter it
              and redistribute it freely, subject to the following
              restrictions:

              1. The origin of this software must not be misrepresented,
                 you must not claim that you wrote the original software.
                 If you use this software in a product, an acknowledgment
                 in the product documentation would be appreciated but is
                 not required.

              2. Altered source versions must be plainly marked as such, and
                 must not be misrepresented as being the original software.

              3. This notice may not be removed or altered from any source
                 distribution.

              4. You must register this software by sending a picture postcard
                 to the author. Use a nice stamp and mention your name, street
                 address, EMail address and any comment you like to say.

History:
Mar 26, 2006 V6.00 New version 6 started
Sep 28, 2008 V6.01 A. Garrels modified UrlEncode() and UrlDecode() to support
             UTF-8 encoding. Moved IsDigit, IsXDigit, XDigit, htoi2 and htoin
             to OverbyteIcsUtils.
Apr 17, 2009 V6.02 A. Garrels added argument CodePage to functions
             UrlEncode() and UrlDecode.
Dec 19, 2009 V6.03 A. Garrels added UrlEncodeToA().
Aug 07, 2010 V6.04 Bj?rnar Nielsen suggested to add an overloaded UrlDecode()
                   that takes a RawByteString URL.
Jan 20, 2012 V6.05 RTT changed ParseUrl() to support URLs starting with "//".
May 2012 - V8.00 - Arno added FireMonkey cross platform support with POSIX/MacOS
                   also IPv6 support, include files now in sub-directory
Mar 10, 2020 V8.64 Added IcsBuildURL, IcsURLtoASCII and IcsURLtoUnicode to
                     support International Domain Names, note these are primarily
                     for display purposes, ICS now handles IDNs internally.
Oct 17, 2020 V8.65 For UrlEncode RFC3986 section 2.1 says four unreserved chars
                      (- . _ -) should not be percent encoded, so added RfcStrict
                      option to ensure this.
                    IcsUrlEncode uses AnsiString and RfcStrict.
                    UrlEncodeEx always uses RfcStrict.


 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *}
unit OverbyteIcsUrl;

interface

{$B-}             { Enable partial boolean evaluation   }
{$T-}             { Untyped pointers                    }
{$X+}             { Enable extended syntax              }
{$I Include\OverbyteIcsDefs.inc}
{$IFDEF DELPHI6_UP}
    {$WARN SYMBOL_PLATFORM   OFF}
    {$WARN SYMBOL_LIBRARY    OFF}
    {$WARN SYMBOL_DEPRECATED OFF}
{$ENDIF}
{$IFNDEF VER80}   { Not for Delphi 1                    }
    {$H+}         { Use long strings                    }
    {$J+}         { Allow typed constant to be modified }
{$ENDIF}
{$IFDEF BCB3_UP}
    {$ObjExportAll On}
{$ENDIF}

uses
{$IFDEF MSWINDOWS}
    {$IFDEF RTL_NAMESPACES}Winapi.Windows{$ELSE}Windows{$ENDIF},
{$ENDIF}
    OverbyteIcsUtils;

const
    IcsUrlVersion        = 865;
    CopyRight : String   = ' TIcsURL (c) 1997-2020 F. Piette V8.65 ';

{ Syntax of an URL: protocol://[user[:password]@]server[:port]/path }
procedure ParseURL(const URL : String;
                   var Proto, User, Pass, Host, Port, Path : String);
function  Posn(const s, t : String; count : Integer) : Integer;
{ V8.64 build a URL without changing any encoding }
function IcsBuildURL(const Proto, User, Pass, Host, Port, Path: string): string ;
{ V8.64 convert the Unicode domain host name in a URL to A-Label (Punycode ASCII) and vice versa }
function IcsURLtoASCII(const Input: string): string ;
function IcsURLtoUnicode(const Input: string): string ;

{ following functions are not for host domain names, but Unicode paths and queries in URLs }
function UrlEncode(const S: String; DstCodePage: LongWord = CP_UTF8;
                                     RfcStrict: Boolean = False): String;          { V8.65 }
function UrlDecode(const S     : String;
                   SrcCodePage : LongWord = CP_ACP;
                   DetectUtf8  : Boolean = TRUE) : String;
{$IFDEF COMPILER12_UP}
                   overload;
function UrlDecode(const S     : RawByteString;
                   SrcCodePage : LongWord = CP_ACP;
                   DetectUtf8  : Boolean = TRUE) : UnicodeString; overload;
{$ENDIF}
function IcsUrlEncode(const AStr: AnsiString; RfcStrict: Boolean = False): AnsiString;  { V8.65 }
function UrlEncodeToA(const S: String; DstCodePage: LongWord = CP_UTF8;
                                           RfcStrict: Boolean = False): AnsiString;   { V8.65 }
function UrlEncodeEx(const S: String): String;                                        { V8.65 }


implementation

type
    TCharSet = set of AnsiChar;
const
    UriProtocolSchemeAllowedChars : TCharSet = ['a'..'z','0'..'9','+','-','.'];


{* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *}
{ Find the count'th occurence of the s string in the t string.              }
{ If count < 0 then look from the back                                      }
function Posn(const s , t : String; Count : Integer) : Integer;
var
    i, h, Last : Integer;
    u          : String;
begin
    u := t;
    if Count > 0 then begin
        Result := Length(t);
        for i := 1 to Count do begin
            h := Pos(s, u);
            if h > 0 then
                u := Copy(u, h + 1, Length(u))
            else begin
                u := '';
                Inc(Result);
            end;
        end;
        Result := Result - Length(u);
    end
    else if Count < 0 then begin
        Last := 0;
        for i := Length(t) downto 1 do begin
            u := Copy(t, i, Length(t));
            h := Pos(s, u);
            if (h <> 0) and ((h + i) <> Last) then begin
                Last := h + i - 1;
                Inc(count);
                if Count = 0 then
                    break;
            end;
        end;
        if Count = 0 then
            Result := Last
        else
            Result := 0;
    end
    else
        Result := 0;
end;


{* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *}
{ Syntax of an URL: protocol://[user[:password]@]server[:port]/path         }
procedure ParseURL(
    const url : String;
    var Proto, User, Pass, Host, Port, Path : String);
var
    p, q, i : Integer;
    s       : String;
    CurPath : String;
begin
    CurPath := Path;
    proto   := '';
    User    := '';
    Pass    := '';
    Host    := '';
    Port    := '';
    Path    := '';

    if Length(url) < 1 then
        Exit;

    { Handle path beginning with "./" or "../".          }
    { This code handle only simple cases !               }
    { Handle path relative to current document directory }
    if (Copy(url, 1, 2) = './') then begin
        p := Posn('/', CurPath, -1);
        if p > Length(CurPath) then
            p := 0;
        if p = 0 then
            CurPath := '/'
        else
            CurPath := Copy(CurPath, 1, p);
        Path := CurPath + Copy(url, 3, Length(url));
        Exit;
    end
    { Handle path relative to current document parent directory }
    else if (Copy(url, 1, 3) = '../') then begin
        p := Posn('/', CurPath, -1);
        if p > Length(CurPath) then
            p := 0;
        if p = 0 then
            CurPath := '/'
        else
            CurPath := Copy(CurPath, 1, p);

        s := Copy(url, 4, Length(url));
        { We could have several levels }
        while TRUE do begin
            CurPath := Copy(CurPath, 1, p-1);
            p := Posn('/', CurPath, -1);
            if p > Length(CurPath) then
                p := 0;
            if p = 0 then
                CurPath := '/'
            else
                CurPath := Copy(CurPath, 1, p);
            if (Copy(s, 1, 3) <> '../') then
                break;
            s := Copy(s, 4, Length(s));
        end;

        Path := CurPath + Copy(s, 1, Length(s));
        Exit;
    end;

    p := pos('://', url);
    q := p;
    if p <> 0 then begin
        S := IcsLowerCase(Copy(url, 1, p - 1));
        for i := 1 to Length(S) do begin
            if not (AnsiChar(S[i]) in UriProtocolSchemeAllowedChars) then begin
                q := i;
                Break;
            end;
        end;
        if q < p then begin
            p     := 0;
            proto := 'http';
        end;
    end;
    if p = 0 then begin
        if (url[1] = '/') then begin
            { Relative path without protocol specified }
            proto := 'http';
            //p     := 1;     { V6.05 }
            if (Length(url) > 1) then begin
                if (url[2] <> '/') then begin
                    { Relative path }
                    Path := Copy(url, 1, Length(url));
                    Exit;
                end
                else
                    p := 2;   { V6.05 }
            end
            else begin        { V6.05 }
                Path := '/';  { V6.05 }
                Exit;         { V6.05 }
            end;
        end
        else if IcsLowerCase(Copy(url, 1, 5)) = 'http:' then begin
            proto := 'http';
            p     := 6;
            if (Length(url) > 6) and (url[7] <> '/') then begin
                { Relative path }
                Path := Copy(url, 6, Length(url));
                Exit;
            end;
        end
        else if IcsLowerCase(Copy(url, 1, 7)) = 'mailto:' then begin
            proto := 'mailto';
            p := pos(':', url);
        end;
    end
    else begin
        proto := IcsLowerCase(Copy(url, 1, p - 1));
        inc(p, 2);
    end;
    s := Copy(url, p + 1, Length(url));

    p := pos('/', s);
    q := pos('?', s);
    if (q > 0) and ((q < p) or (p = 0)) then
        p := q;
    if p = 0 then
        p := Length(s) + 1;
    Path := Copy(s, p, Length(s));
    s    := Copy(s, 1, p-1);

    { IPv6 URL notation, for instance "[2001:db8::3]" }
    p := Pos('[', s);
    q := Pos(']', s);
    if (p = 1) and (q > 1) then
    begin
        Host := Copy(s, 2, q - 2);
        s := Copy(s, q + 1, Length(s));
    end;

    p := Posn(':', s, -1);
    if p > Length(s) then
        p := 0;
    q := Posn('@', s, -1);
    if q > Length(s) then
        q := 0;
    if (p = 0) and (q = 0) then begin   { no user, password or port }
        if Host = '' then
            Host := s;
        Exit;
    end
    else if q < p then begin  { a port given }
        Port := Copy(s, p + 1, Length(s));
        if Host = '' then
            Host := Copy(s, q + 1, p - q - 1);
        if q = 0 then
            Exit; { no user, password }
        s := Copy(s, 1, q - 1);
    end
    else begin
        if Host = '' then
            Host := Copy(s, q + 1, Length(s));
        s := Copy(s, 1, q - 1);
    end;
    p := pos(':', s);
    if p = 0 then
        User := s
    else begin
        User := Copy(s, 1, p - 1);
        Pass := Copy(s, p + 1, Length(s));
    end;
end;


{* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *}
{ V8.64 build a URL without changing any encoding }
function IcsBuildURL (const Proto, User, Pass, Host, Port, Path: string): string ;
begin
    Result := Proto + '://' ;
    if User <> '' then begin
        Result := Result + User ;
        if Pass <> '' then Result := Result + ':' + Pass ;
        Result := Result + '@' ;
    end ;
    Result := Result + Host ;
    if Port <> '' then Result := Result + ':' + Port ;
    if Path <> '' then begin
        if Path[1] <> '/' then Result := Result + '/' ;
        Result := Result + Path ;
    end;
end ;


{* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *}
{ V8.64 convert the Unicode domain host name in a URL to A-Label (Punycode ASCII) }
function IcsURLtoASCII (const Input: string): string ;
var
    Proto, User, Pass, Host, Port, Path: string;
begin
    ParseURL(Input, Proto, User, Pass, Host, Port, Path);
    Result := IcsBuildURL(Proto, User, Pass, IcsIDNAToASCII(Host), Port, Path);
end ;


{* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *}
{ V8.64 convert the A-Label (Punycode ASCII) domain host name in a URL to Unicode }
{ not does not change path }
function IcsURLtoUnicode (const Input: string): string ;
var
    Proto, User, Pass, Host, Port, Path: string;
begin
    ParseURL(Input, Proto, User, Pass, Host, Port, Path);
    Result := IcsBuildURL(Proto, User, Pass, IcsIDNAToUnicode(Host), Port, Path);
end ;


{* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *}
{ V8.65 RFC3986 section 2.1 says four unreserved chars (- . _ -) should not
  be percent encoded, so added RfcStrict option to ensure this, AnsiStrings }
function IcsUrlEncode(const AStr: AnsiString; RfcStrict: Boolean = False): AnsiString;
var
    I, J   : Integer;
    RStr   : AnsiString;
    HexStr : String[2];
    ACh    : AnsiChar;
begin
    SetLength(RStr, Length(AStr) * 3);
    J := 0;
    for I := 1 to Length(AStr) do begin
        ACh := AStr[I];
        if ((ACh >= '0') and (ACh <= '9')) or
              ((ACh >= 'a') and (ACh <= 'z')) or
                  ((ACh >= 'A') and (ACh <= 'Z')) then begin
            Inc(J);
            RStr[J] := ACh;
        end
        else if RfcStrict and ((ACh = '.') or (ACh = '-') or
                         (ACh = '_')  or (ACh = '~')) then begin
            Inc(J);
            RStr[J] := ACh;
        end
        else begin
            Inc(J);
            RStr[J] := '%';
            HexStr  := IcsIntToHexA(Ord(ACh), 2);
            Inc(J);
            RStr[J] := HexStr[1];
            Inc(J);
            RStr[J] := HexStr[2];
        end;
    end;
    SetLength(RStr, J);
    Result := RStr;
end;

{* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *}
{ V8.65 RFC3986 section 2.1 says four unreserved chars (- . _ -) should not
  be percent encoded, so added RfcStrict option to ensure this, Strings }
function UrlEncodeToA(const S: String; DstCodePage: LongWord = CP_UTF8;
                                            RfcStrict: Boolean = False): AnsiString;
var
    AStr   : AnsiString;
begin
{$IFDEF COMPILER12_UP}
    AStr := UnicodeToAnsi(S, DstCodePage);
{$ELSE}
    if DstCodePage = CP_UTF8 then
        AStr := StringToUtf8(S)
    else
        AStr := S;
{$ENDIF}
    Result := IcsUrlEncode(AStr, RfcStrict);
end;


{* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *}
function UrlEncode(const S: String; DstCodePage: LongWord = CP_UTF8;
                                             RfcStrict: Boolean = False): String; { V8.65 added RfcStrict }
begin
    Result := String(UrlEncodeToA(S, DstCodePage, RfcStrict));
end;


{* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *}
function UrlEncodeEx(const S: String): String;                                   { V8.65 }
begin
    Result := String(UrlEncodeToA(S, CP_UTF8, True));
end;


{* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *}
function UrlDecode(const S : String; SrcCodePage: LongWord = CP_ACP;
  DetectUtf8: Boolean = TRUE) : String;
var
    I, J, L : Integer;
    U8Str   : AnsiString;
    Ch      : AnsiChar;
begin
    L := Length(S);
    SetLength(U8Str, L);
    I := 1;
    J := 0;
    while (I <= L) and (S[I] <> '&') do begin
        Ch := AnsiChar(S[I]);
        if Ch = '%' then begin
            Ch := AnsiChar(htoi2(PChar(@S[I + 1])));
            Inc(I, 2);
        end
        else if Ch = '+' then
            Ch := ' ';
        Inc(J);
        U8Str[J] := Ch;
        Inc(I);
    end;
    SetLength(U8Str, J);
    if (SrcCodePage = CP_UTF8) or (DetectUtf8 and IsUtf8Valid(U8Str)) then
{$IFDEF COMPILER12_UP}
        Result := Utf8ToStringW(U8Str)
    else
        Result := AnsiToUnicode(U8Str, SrcCodePage);
{$ELSE}
        Result := Utf8ToStringA(U8Str)
    else
        Result := U8Str;
{$ENDIF}
end;


{* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *}
{$IFDEF COMPILER12_UP}
function UrlDecode(const S: RawByteString; SrcCodePage: LongWord = CP_ACP;
  DetectUtf8: Boolean = TRUE): UnicodeString;
var
    I, J, L : Integer;
    U8Str   : AnsiString;
    Ch      : AnsiChar;
begin
    L := Length(S);
    SetLength(U8Str, L);
    I := 1;
    J := 0;
    while (I <= L) and (S[I] <> '&') do begin
        Ch := AnsiChar(S[I]);
        if Ch = '%' then begin
            Ch := AnsiChar(htoi2(PAnsiChar(@S[I + 1])));
            Inc(I, 2);
        end
        else if Ch = '+' then
            Ch := ' ';
        Inc(J);
        U8Str[J] := Ch;
        Inc(I);
    end;
    SetLength(U8Str, J);
    if (SrcCodePage = CP_UTF8) or (DetectUtf8 and IsUtf8Valid(U8Str)) then
        Result := Utf8ToStringW(U8Str)
    else
        Result := AnsiToUnicode(U8Str, SrcCodePage);
end;
{$ENDIF}


{* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *}

end.
