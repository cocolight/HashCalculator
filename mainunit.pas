unit mainunit;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, StdCtrls, ExtCtrls,
  DCPmd5, DCPsha256, Clipbrd, ComCtrls, Windows, LazUTF8;

type

  // 进度回调类型
  TProgressCallback = procedure(Current, Total: Int64; var Cancel: Boolean) of object;

  // 哈希计算线程 - 使用内存映射文件
  THashThread = class(TThread)
  private
    FFileName: string;
    FUpperCase: Boolean;
    FMD5Result: string;
    FSHA256Result: string;
    FErrorMsg: string;
    FOnProgress: TProgressCallback;
    FOnComplete: TNotifyEvent;
    FCurrentPos: Int64;
    FTotalSize: Int64;
    FCancel: Boolean;
    procedure DoProgress;
    procedure DoComplete;
    procedure DoError;
    procedure UpdateProgress;
    procedure Complete;
    procedure Error;
    function BytesToHex(const Bytes: array of Byte; UpperCase: Boolean): string;
  protected
    procedure Execute; override;
  public
    constructor Create(const FileName: string; UpperCase: Boolean);
    procedure Cancel;
    property MD5Result: string read FMD5Result;
    property SHA256Result: string read FSHA256Result;
    property ErrorMsg: string read FErrorMsg;
    property OnProgress: TProgressCallback read FOnProgress write FOnProgress;
    property OnComplete: TNotifyEvent read FOnComplete write FOnComplete;
    property TotalSize: Int64 read FTotalSize;
  end;

  { TMainForm }

  TMainForm = class(TForm)
    btnBrowseFile: TButton;
    btnCalculate: TButton;
    btnCopyHash: TButton;
    btnVerify: TButton;
    btnClear: TButton;
    btnCancel: TButton;
    chkSHA256: TCheckBox;
    chkMD5: TCheckBox;
    chkUpperCase: TCheckBox;
    edtFilePath: TEdit;
    edtVerifyMD5: TEdit;
    edtVerifySHA256: TEdit;
    GroupBox1: TGroupBox;
    GroupBox2: TGroupBox;
    GroupBox3: TGroupBox;
    GroupBoxFile: TGroupBox;
    GroupBoxSettings: TGroupBox;
    GroupBoxResult: TGroupBox;
    GroupBoxVerify: TGroupBox;
    lblStatus: TLabel;
    lblFile: TLabel;
    lblVerifyMD5: TLabel;
    lblVerifySHA256: TLabel;
    lblMD5Status: TLabel;
    lblSHA256Status: TLabel;
    memoResult: TMemo;
    OpenDialog: TOpenDialog;
    Panel2: TPanel;
    PanelButtons: TPanel;
    ProgressBar: TProgressBar;
    procedure btnBrowseFileClick(Sender: TObject);
    procedure btnCalculateClick(Sender: TObject);
    procedure btnClearClick(Sender: TObject);
    procedure btnCancelClick(Sender: TObject);
    procedure btnCopyHashClick(Sender: TObject);
    procedure btnVerifyClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
  private
    FMD5Hash: string;
    FSHA256Hash: string;
    FHashThread: THashThread;
    FStartTime: TDateTime;
    FFileName: string;
    FFileSize: Int64;
    FFileDate: TDateTime;
    function CalculateMD5(const FileName: string): string;
    function CalculateSHA256(const FileName: string): string;
    function FormatFileSize(Size: Int64): string;
    procedure UpdateVerifyStatus;
    procedure OnHashProgress(Current, Total: Int64; var Cancel: Boolean);
    procedure OnHashComplete(Sender: TObject);
    procedure SetUIState(Calculating: Boolean);
    procedure ShowStatus(const Msg: string; IsError: Boolean = False);
    procedure UpdateResultMemo;

  public

  end;

var
  MainForm: TMainForm;

implementation

{$R *.lfm}

// 独立的全局函数
function BytesToHex(const Bytes: array of Byte; UpperCase: Boolean): string;
const
  HexDigitsLower: array[0..15] of Char = '0123456789abcdef';
  HexDigitsUpper: array[0..15] of Char = '0123456789ABCDEF';
var
  i: Integer;
  HexDigits: array[0..15] of Char;
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

{=================== THashThread 实现 ===================}

constructor THashThread.Create(const FileName: string; UpperCase: Boolean);
begin
  inherited Create(True);
  FFileName := FileName;
  FUpperCase := UpperCase;
  FCancel := False;
  FreeOnTerminate := False;
end;

procedure THashThread.Cancel;
begin
  FCancel := True;
end;

procedure THashThread.DoProgress;
begin
  if FCancel then Exit;

  if Assigned(FOnProgress) then
    FOnProgress(FCurrentPos, FTotalSize, FCancel);
end;

procedure THashThread.DoComplete;
begin
  if Assigned(FOnComplete) then
    FOnComplete(Self);
end;

procedure THashThread.DoError;
begin
  if Assigned(FOnComplete) then
    FOnComplete(Self);
end;

procedure THashThread.UpdateProgress;
begin
  if not FCancel then
    Queue(@DoProgress);
end;

procedure THashThread.Complete;
begin
  Queue(@DoComplete);
end;

procedure THashThread.Error;
begin
  Queue(@DoError);
end;

function THashThread.BytesToHex(const Bytes: array of Byte; UpperCase: Boolean): string;
const
  HexDigitsLower: array[0..15] of Char = '0123456789abcdef';
  HexDigitsUpper: array[0..15] of Char = '0123456789ABCDEF';
var
  i: Integer;
  HexDigits: array[0..15] of Char;
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

// 内存映射文件版本的核心计算
procedure THashThread.Execute;
const
  VIEW_SIZE = 64 * 1024 * 1024; // 64MB 视图，减少映射次数
  UPDATE_INTERVAL = 256 * 1024 * 1024; // 每 256MB 更新一次进度
var
  MD5: TDCP_md5;
  SHA256: TDCP_sha256;
  FileHandle: THandle;
  MapHandle: THandle;
  MapView: Pointer;
  FileSizeHigh, FileSizeLow: DWORD;
  FileSize: Int64;
  Offset: Int64;
  BytesToProcess: DWORD;
  HashBytes: array of Byte;
  LastUpdate: Int64;
  WideFileName: WideString;
begin
  FMD5Result := '';
  FSHA256Result := '';
  FErrorMsg := '';
  FileHandle := INVALID_HANDLE_VALUE;
  MapHandle := 0;
  MapView := nil;

  try
    WideFileName := UTF8ToUTF16(FFileName);
    // 1. 打开文件
    FileHandle := CreateFileW(
      PWideChar(WideFileName),
      GENERIC_READ,
      FILE_SHARE_READ or FILE_SHARE_WRITE,
      nil,
      OPEN_EXISTING,
      FILE_FLAG_SEQUENTIAL_SCAN,
      0
    );

    if FileHandle = INVALID_HANDLE_VALUE then
      raise Exception.Create('无法打开文件: ' + SysErrorMessage(GetLastError));

    // 2. 获取文件大小
    FileSizeLow := GetFileSize(FileHandle, @FileSizeHigh);
    FileSize := (Int64(FileSizeHigh) shl 32) or FileSizeLow;
    FTotalSize := FileSize;

    if FileSize = 0 then
      raise Exception.Create('文件为空');

    // 3. 创建文件映射
    MapHandle := CreateFileMapping(
      FileHandle,
      nil,
      PAGE_READONLY,
      0,
      0,
      nil
    );

    if MapHandle = 0 then
      raise Exception.Create('无法创建文件映射: ' + SysErrorMessage(GetLastError));

    // 4. 初始化哈希算法
    MD5 := TDCP_md5.Create(nil);
    SHA256 := TDCP_sha256.Create(nil);
    try
      MD5.Init;
      SHA256.Init;

      Offset := 0;
      LastUpdate := 0;
      FCurrentPos := 0;

      // 发送初始进度
      UpdateProgress;

      // 5. 循环映射视图并计算
      while (Offset < FileSize) and not FCancel do
      begin
        // 计算本次要处理的字节数
        if FileSize - Offset > VIEW_SIZE then
          BytesToProcess := VIEW_SIZE
        else
          BytesToProcess := DWORD(FileSize - Offset);

        // 映射视图
        MapView := MapViewOfFile(
          MapHandle,
          FILE_MAP_READ,
          DWORD(Offset shr 32),
          DWORD(Offset and $FFFFFFFF),
          BytesToProcess
        );

        if MapView = nil then
          raise Exception.Create('无法映射视图: ' + SysErrorMessage(GetLastError));

        try
          // 更新哈希 - 这是核心计算
          MD5.Update(MapView^, BytesToProcess);
          SHA256.Update(MapView^, BytesToProcess);

          Inc(Offset, BytesToProcess);
          FCurrentPos := Offset;

          // 修改：进度更新 - 增加取消检查
          if not FCancel then
          begin
            if (FCurrentPos - LastUpdate >= UPDATE_INTERVAL) or (FCurrentPos >= FileSize) then
            begin
              UpdateProgress;
              LastUpdate := FCurrentPos;
            end;
          end;
        finally
          UnmapViewOfFile(MapView);
          MapView := nil;
        end;
end;

// 修改：改进取消处理
if FCancel then
begin
  FErrorMsg := '用户取消';
  // 不调用 Complete，直接调用 Error
  Error;
  Exit;  // 退出，进入 finally 清理
end;


      // 6. 获取最终结果
      SetLength(HashBytes, 16);
      MD5.Final(HashBytes[0]);
      FMD5Result := BytesToHex(HashBytes, FUpperCase);

      SetLength(HashBytes, 32);
      SHA256.Final(HashBytes[0]);
      FSHA256Result := BytesToHex(HashBytes, FUpperCase);

    finally
      MD5.Free;
      SHA256.Free;
    end;

    Complete;

  except
    on E: Exception do
    begin
      FErrorMsg := E.Message;
      Error;
    end;
  end;

  // 清理资源
  if MapHandle <> 0 then
    CloseHandle(MapHandle);
  if FileHandle <> INVALID_HANDLE_VALUE then
    CloseHandle(FileHandle);
end;


{=================== TMainForm 辅助方法 ===================}

function TMainForm.FormatFileSize(Size: Int64): string;
const
  KB = 1024;
  MB = 1024 * KB;
  GB = 1024 * MB;
begin
  if Size < KB then
    Result := Format('%d B', [Size])
  else if Size < MB then
    Result := Format('%.1f KB', [Size / KB])
  else if Size < GB then
    Result := Format('%.1f MB', [Size / MB])
  else
    Result := Format('%.2f GB', [Size / GB]);
end;

procedure TMainForm.ShowStatus(const Msg: string; IsError: Boolean = False);
begin
  lblStatus.Caption := Msg;
  if IsError then
    lblStatus.Font.Color := clRed
  else
    lblStatus.Font.Color := clGreen;
end;

procedure TMainForm.SetUIState(Calculating: Boolean);
begin
  btnCalculate.Visible := not Calculating;
  btnCancel.Visible := Calculating;
  btnBrowseFile.Enabled := not Calculating;
  btnClear.Enabled := not Calculating;
  btnVerify.Enabled := not Calculating and (FMD5Hash <> '');
  btnCopyHash.Enabled := not Calculating and ((FMD5Hash <> '') or (FSHA256Hash <> ''));

  if Calculating then
  begin
    // memoResult.Clear;
    FMD5Hash := '';
    FSHA256Hash := '';
    UpdateResultMemo;
    ProgressBar.Position := 0;
    FStartTime := Now;
    ShowStatus('计算中...');
    // 修改：确保取消按钮可用
    btnCancel.Enabled := True;
  end
  else
  begin
    // 修改：计算结束后重置进度条
    ProgressBar.Position := 0;
  end;
end;


procedure TMainForm.OnHashProgress(Current, Total: Int64; var Cancel: Boolean);
var
  Percent: Integer;
  Elapsed: Double;
  Speed: Double;
  Remaining: Double;
  StatusMsg: string;
begin
  if Total <= 0 then Exit;

  Percent := Round((Current / Total) * 100);

  // 限制进度条更新频率
  if Abs(ProgressBar.Position - Percent) < 1 then Exit;

  ProgressBar.Position := Percent;

  // 构建状态信息
  StatusMsg := Format('计算中 %d%% (%s / %s)',
    [Percent, FormatFileSize(Current), FormatFileSize(Total)]);

  // 计算速度和剩余时间
  Elapsed := (Now - FStartTime) * 24 * 3600;
  if Elapsed > 0 then
  begin
    Speed := Current / Elapsed;
    Remaining := (Total - Current) / Speed;

    // 合并显示:百分比 + 大小 + 速度 + 剩余时间
    StatusMsg := Format('计算中 %d%% | %s/s | 剩余%d秒 | %s/%s',
      [Percent,
       FormatFileSize(Round(Speed)),
       Round(Remaining),
       FormatFileSize(Current),
       FormatFileSize(Total)]);
  end;

  ShowStatus(StatusMsg);

  // 强制刷新
  lblStatus.Repaint;
  ProgressBar.Repaint;
end;

procedure TMainForm.OnHashComplete(Sender: TObject);
var
  Elapsed: Double;
  WasCancelled: Boolean;
begin
  Elapsed := (Now - FStartTime) * 24 * 3600;

  // 修改：检查是否是用户取消
  WasCancelled := (FHashThread.ErrorMsg = '用户取消');

  if FHashThread.ErrorMsg <> '' then
  begin
    // 错误处理
    if not WasCancelled then
      ShowMessage('错误: ' + FHashThread.ErrorMsg);

    FMD5Hash := '';
    FSHA256Hash := '';
    UpdateResultMemo;

    if WasCancelled then
      ShowStatus('已取消')
    else
      ShowStatus('计算失败', True);
  end
  else
  begin
    FMD5Hash := FHashThread.MD5Result;
    FSHA256Hash := FHashThread.SHA256Result;

    UpdateResultMemo;
    ShowStatus(Format('计算完成 | 耗时 %.1f秒', [Elapsed]));
    UpdateVerifyStatus;
  end;

  // 修改：安全释放线程
  FHashThread.Free;
  FHashThread := nil;
  SetUIState(False);

  // 修改：如果是取消后的清理，执行完整清理
  if WasCancelled then
  begin
    // 检查是否需要执行完整清理（btnClearClick 触发的取消）
    // 这里可以添加一个标志来判断
    // 暂时不做额外清理，让用户再次点击清空按钮
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
  FHashThread := nil;
  FFileName := '';
  FFileSize := 0;
  FFileDate := 0;
  FMD5Hash := '';
  FSHA256Hash := '';

  lblMD5Status.Caption := '-';
  lblSHA256Status.Caption := '-';
  ProgressBar.Position := 0;
  chkUpperCase.Checked := True;
  memoResult.Clear;

  ShowStatus('就绪');
  SetUIState(False);
end;

procedure TMainForm.FormDestroy(Sender: TObject);
begin
  if Assigned(FHashThread) then
  begin
    FHashThread.Cancel;
    FHashThread.WaitFor;
    FHashThread.Free;
  end;
end;

procedure TMainForm.btnBrowseFileClick(Sender: TObject);
var
  SearchRec: TSearchRec;
begin
  if OpenDialog.Execute then
  begin
    FFileName := OpenDialog.FileName;
    edtFilePath.Text := FFileName;

    // 获取文件信息
    if FindFirst(FFileName, faAnyFile, SearchRec) = 0 then
    begin
      FFileSize := SearchRec.Size;
      FFileDate := FileDateToDateTime(SearchRec.Time);
      SysUtils.FindClose(SearchRec);

    end
    else
    begin
      FFileSize := 0;
      FFileDate := 0;
    end;

    // 清空结果
    FMD5Hash := '';
    FSHA256Hash := '';
    // memoResult.Clear;
    UpdateResultMemo;
    lblMD5Status.Caption := '-';
    lblSHA256Status.Caption := '-';
    ProgressBar.Position := 0;

    ShowStatus('已选择文件');
  end;
end;

procedure TMainForm.UpdateResultMemo;
var
  FileNameOnly: string;
begin
  memoResult.Clear;

  // 文件名称（仅文件名，不含路径）
  FileNameOnly := ExtractFileName(FFileName);
  memoResult.Lines.Add('文件名称: ' + FileNameOnly);

  // 文件大小
  if FFileSize > 0 then
    memoResult.Lines.Add('文件大小: ' + FormatFileSize(FFileSize))
  else
    memoResult.Lines.Add('文件大小: -');

  // 修改日期
  if FFileDate > 0 then
    memoResult.Lines.Add('修改日期: ' + FormatDateTime('yyyy-mm-dd hh:nn:ss', FFileDate))
  else
    memoResult.Lines.Add('修改日期: -');

  // 哈希值
  if FMD5Hash <> '' then
    memoResult.Lines.Add('MD5:  ' + FMD5Hash)
  else
    memoResult.Lines.Add('MD5:  -');

  if FSHA256Hash <> '' then
    memoResult.Lines.Add('SHA-256:  ' + FSHA256Hash)
  else
    memoResult.Lines.Add('SHA-256:  -');
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

  // 创建并启动线程
  FHashThread := THashThread.Create(FileName, chkUpperCase.Checked);
  FHashThread.OnProgress := @OnHashProgress;
  FHashThread.OnComplete := @OnHashComplete;

  SetUIState(True);
  FHashThread.Start;
end;

procedure TMainForm.btnCancelClick(Sender: TObject);
begin
  if Assigned(FHashThread) then
  begin
    FHashThread.Cancel;
    ShowStatus('正在取消...');
    // 修改：禁用取消按钮，防止重复点击
    btnCancel.Enabled := False;
  end;
end;


procedure TMainForm.btnVerifyClick(Sender: TObject);
var
  verifyMD5Empty, verifySHA256Empty: Boolean;
begin
  // 第一步:检查计算结果是否为空（原逻辑保留）
  if (FMD5Hash = '') and (FSHA256Hash = '') then
  begin
    ShowStatus('请先计算哈希值', True); // 提示语更准确
    Exit;
  end;

  // 第二步:检查验证输入框是否为空
  verifyMD5Empty := Trim(edtVerifyMD5.Text) = '';
  verifySHA256Empty := Trim(edtVerifySHA256.Text) = '';

  // 两个输入框都空，提示并退出
  if verifyMD5Empty and verifySHA256Empty then
  begin
    ShowStatus('请至少填写一个待验证的哈希值', True);
    Exit;
  end;

  // 第三步:执行验证（原逻辑）
  UpdateVerifyStatus;
  ShowStatus('验证完成');
end;

procedure TMainForm.btnClearClick(Sender: TObject);
begin
  // 修改：如果线程正在运行，只设置取消标志
  if Assigned(FHashThread) then
  begin
    FHashThread.Cancel;
    // 移除 WaitFor，让线程自然结束
    // 禁用清空按钮，防止重复点击
    btnClear.Enabled := False;
    ShowStatus('正在取消并清理...');
    // 注意：实际清理会在 OnHashComplete 中完成
    Exit;
  end;

  // 如果没有线程运行，直接清空
  edtFilePath.Text := '';
  edtVerifyMD5.Text := '';
  edtVerifySHA256.Text := '';

  FFileName := '';
  FFileSize := 0;
  FFileDate := 0;
  FMD5Hash := '';
  FSHA256Hash := '';

  memoResult.Clear;
  lblMD5Status.Caption := '-';
  lblSHA256Status.Caption := '-';
  ProgressBar.Position := 0;

  ShowStatus('就绪');
end;


procedure TMainForm.btnCopyHashClick(Sender: TObject);
begin
  if memoResult.Lines.Count > 2   then
  begin
    Clipboard.AsText := memoResult.Text;
    ShowStatus('结果已复制到剪贴板');
  end
  else
     ShowStatus('请先计算, 无内容可复制', True);
end;

end.
