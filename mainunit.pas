unit mainunit;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, StdCtrls, ExtCtrls,
  DCPmd5, DCPsha256, Clipbrd, Windows;

type

  { TMainForm }

  TMainForm = class(TForm)
    btnBrowseFile: TButton;
    btnCalculate: TButton;
    btnCopyMD5: TButton;
    btnCopySHA256: TButton;
    btnVerify: TButton;
    btnClear: TButton;
    chkUpperCase: TCheckBox;
    edtFilePath: TEdit;
    edtVerifyMD5: TEdit;
    edtVerifySHA256: TEdit;
    GroupBoxFile: TGroupBox;
    GroupBoxSettings: TGroupBox;
    GroupBoxResult: TGroupBox;
    GroupBoxVerify: TGroupBox;
    lblFile: TLabel;
    lblMD5Result: TLabel;
    lblSHA256Result: TLabel;
    lblVerifyMD5: TLabel;
    lblVerifySHA256: TLabel;
    lblMD5Status: TLabel;
    lblSHA256Status: TLabel;
    OpenDialog: TOpenDialog;
    PanelButtons: TPanel;
    procedure btnBrowseFileClick(Sender: TObject);
    procedure btnCalculateClick(Sender: TObject);
    procedure btnClearClick(Sender: TObject);
    procedure btnCopyHashClick(Sender: TObject);
    procedure btnCopyMD5Click(Sender: TObject);
    procedure btnCopySHA256Click(Sender: TObject);
    //procedure btnCopyHash(Sender: TObject);
    procedure btnVerifyClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    FMD5Hash: string;
    FSHA256Hash: string;
    function CalculateMD5(const FileName: string): string;
    function CalculateSHA256(const FileName: string): string;
    function BytesToHex(const Bytes: array of Byte; UpperCase: Boolean): string;
    procedure UpdateVerifyStatus;
  public
  end;

var
  MainForm: TMainForm;

implementation

{$R *.lfm}

{ 辅助函数 }

function TMainForm.BytesToHex(const Bytes: array of Byte; UpperCase: Boolean): string;
const
  HexDigitsLower: array[0..15] of Char = '0123456789abcdef';
  HexDigitsUpper: array[0..15] of Char = '0123456789ABCDEF';
var
  i: Integer;
  HexDigits: array[0..15] of Char = '000000';
begin
  Result := '';
  if UpperCase then
    Move(HexDigitsUpper, HexDigits, SizeOf(HexDigits))
  else
    Move(HexDigitsLower, HexDigits, SizeOf(HexDigits));

  SetLength(Result, Length(Bytes) * 2);
  for i := 0 to High(Bytes) do
  begin
    Result[i * 2 + 1] := HexDigits[Bytes[i] shr 4];
    Result[i * 2 + 2] := HexDigits[Bytes[i] and $0F];
  end;
end;

{ MD5 计算 }

function TMainForm.CalculateMD5(const FileName: string): string;
var
  MD5: TDCP_md5;
  FileStream: TFileStream;
  HashBytes: array of Byte;
  Buffer: array[0..8191] of Byte;
  BytesRead: Integer;
begin
  Result := '';

  // 添加初始化消除提示
  FillChar(Buffer, SizeOf(Buffer), 0);
  SetLength(HashBytes, 64);
  FillChar(HashBytes[0], Length(HashBytes), 0);

  FileStream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    MD5 := TDCP_md5.Create(nil);
    try
      MD5.Init;
      repeat
        BytesRead := FileStream.Read(Buffer, SizeOf(Buffer));
        if BytesRead > 0 then
          MD5.Update(Buffer, BytesRead);
      until BytesRead = 0;
      SetLength(HashBytes, 16);
      MD5.Final(HashBytes[0]);
      Result := BytesToHex(HashBytes, chkUpperCase.Checked);
    finally
      MD5.Free;
    end;
  finally
    FileStream.Free;
  end;
end;

{ SHA-256 计算 }

function TMainForm.CalculateSHA256(const FileName: string): string;
var
  SHA256: TDCP_sha256;
  FileStream: TFileStream;
  HashBytes: array of Byte;
  Buffer: array[0..8191] of Byte;
  BytesRead: Integer;
begin
  Result := '';

  // 添加初始化消除提示
  FillChar(Buffer, SizeOf(Buffer), 0);
  SetLength(HashBytes, 64);
  FillChar(HashBytes[0], Length(HashBytes), 0);

  FileStream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    SHA256 := TDCP_sha256.Create(nil);
    try
      SHA256.Init;
      repeat
        BytesRead := FileStream.Read(Buffer, SizeOf(Buffer));
        if BytesRead > 0 then
          SHA256.Update(Buffer, BytesRead);
      until BytesRead = 0;
      SetLength(HashBytes, 32);
      SHA256.Final(HashBytes[0]);
      Result := BytesToHex(HashBytes, chkUpperCase.Checked);
    finally
      SHA256.Free;
    end;
  finally
    FileStream.Free;
  end;
end;

{ 更新验证状态 }

procedure TMainForm.UpdateVerifyStatus;
var
  InputMD5, InputSHA256: string;
begin
  // 验证 MD5
  InputMD5 := Trim(edtVerifyMD5.Text);
  if (FMD5Hash <> '') and (InputMD5 <> '') then
  begin
    if SameText(FMD5Hash, InputMD5) then
    begin
      lblMD5Status.Caption := '✓ 通过';
      lblMD5Status.Font.Color := clGreen;
    end
    else
    begin
      lblMD5Status.Caption := '✗ 失败';
      lblMD5Status.Font.Color := clRed;
    end;
  end
  else
  begin
    lblMD5Status.Caption := '-';
    lblMD5Status.Font.Color := clDefault;
  end;

  // 验证 SHA-256
  InputSHA256 := Trim(edtVerifySHA256.Text);
  if (FSHA256Hash <> '') and (InputSHA256 <> '') then
  begin
    if SameText(FSHA256Hash, InputSHA256) then
    begin
      lblSHA256Status.Caption := '✓ 通过';
      lblSHA256Status.Font.Color := clGreen;
    end
    else
    begin
      lblSHA256Status.Caption := '✗ 失败';
      lblSHA256Status.Font.Color := clRed;
    end;
  end
  else
  begin
    lblSHA256Status.Caption := '-';
    lblSHA256Status.Font.Color := clDefault;
  end;
end;

{ 事件处理 }

procedure TMainForm.FormCreate(Sender: TObject);
begin
  FMD5Hash := '';
  FSHA256Hash := '';
  lblMD5Result.Caption := '(未计算)';
  lblSHA256Result.Caption := '(未计算)';
  lblMD5Status.Caption := '-';
  lblSHA256Status.Caption := '-';
  chkUpperCase.Checked := True;
end;

procedure TMainForm.btnBrowseFileClick(Sender: TObject);
begin
  if OpenDialog.Execute then
  begin
    edtFilePath.Text := OpenDialog.FileName;
  end;
end;

procedure TMainForm.btnCalculateClick(Sender: TObject);
var
  FileName: string;
begin
  FileName := edtFilePath.Text;
  if FileName = '' then
  begin
    ShowMessage('请选择文件');
    Exit;
  end;

  if not FileExists(FileName) then
  begin
    ShowMessage('文件不存在');
    Exit;
  end;

  Screen.Cursor := crHourGlass;
  try
    // 同时计算两种哈希
    FMD5Hash := CalculateMD5(FileName);
    FSHA256Hash := CalculateSHA256(FileName);

    // 显示结果
    lblMD5Result.Caption := FMD5Hash;
    lblSHA256Result.Caption := FSHA256Hash;

    // 更新验证状态（如果验证框已有内容）
    UpdateVerifyStatus;
  finally
    Screen.Cursor := crDefault;
  end;
end;

procedure TMainForm.btnCopyMD5Click(Sender: TObject);
begin
  if FMD5Hash <> '' then
  begin
    Clipboard.AsText := FMD5Hash;
    ShowMessage('MD5 已复制');
  end
  else
    ShowMessage('请先计算');
end;

procedure TMainForm.btnCopySHA256Click(Sender: TObject);
begin
  if FSHA256Hash <> '' then
  begin
    Clipboard.AsText := FSHA256Hash;
    ShowMessage('SHA-256 已复制');
  end
  else
    ShowMessage('请先计算');
end;

procedure TMainForm.btnVerifyClick(Sender: TObject);
begin
  if (FMD5Hash = '') and (FSHA256Hash = '') then
  begin
    ShowMessage('请先计算哈希值');
    Exit;
  end;

  UpdateVerifyStatus;
end;

procedure TMainForm.btnClearClick(Sender: TObject);
begin
  edtFilePath.Text := '';
  edtVerifyMD5.Text := '';
  edtVerifySHA256.Text := '';
  FMD5Hash := '';
  FSHA256Hash := '';
  lblMD5Result.Caption := '(未计算)';
  lblSHA256Result.Caption := '(未计算)';
  lblMD5Status.Caption := '-';
  lblSHA256Status.Caption := '-';
  lblMD5Status.Font.Color := clDefault;
  lblSHA256Status.Font.Color := clDefault;
end;

procedure TMainForm.btnCopyHashClick(Sender: TObject);
begin
  if (FMD5Hash <> '') or (FSHA256Hash <> '')   then
  begin
    Clipboard.AsText := 'MD5: '+ FMD5Hash + LineEnding + 'SHA-256: ' + FSHA256Hash;
    showMessage('Hash结果已复制');
  end
  else
     ShowMessage('请先计算');
end;

end.
