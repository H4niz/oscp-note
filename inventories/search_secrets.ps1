param(
    # Đường dẫn thư mục gốc để quét (mặc định là C:\)
    [string]$SearchPath = "C:\",
    
    # Danh sách các đuôi tệp cần quét (có thể mở rộng)
    [string[]]$FileExtensions = @("*.txt", "*.log", "*.conf", "*.ini"),
    
    # Danh sách từ khóa cần tìm kiếm
    [string[]]$Keywords = @("password:", "oscp{"),
    
    # File xuất kết quả
    [string]$OutputFile = "ScanResults.txt"
)

Write-Host "Bắt đầu quét trong thư mục: $SearchPath" -ForegroundColor Cyan
Write-Host "Tìm kiếm các từ khóa: $($Keywords -join ', ')" -ForegroundColor Cyan
Write-Host "Kết quả sẽ được lưu vào file: $OutputFile" -ForegroundColor Cyan
Write-Host "--------------------------------------------`n"

# Mảng chứa kết quả
$results = @()

foreach ($extension in $FileExtensions) {
    # Lấy danh sách các tệp có đuôi tương ứng
    Get-ChildItem -Path $SearchPath -Filter $extension -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $file = $_
        try {
            # Tìm kiếm các dòng chứa từ khóa
            $matches = Select-String -Path $file.FullName -Pattern ($Keywords -join "|") -ErrorAction SilentlyContinue
            if ($matches) {
                foreach ($match in $matches) {
                    $outputLine = "File: $($file.FullName) - Line $($match.LineNumber): $($match.Line.Trim())"
                    
                    # Hiển thị ngay kết quả tìm thấy
                    Write-Host $outputLine -ForegroundColor Green
                    
                    # Lưu kết quả vào mảng
                    $results += $outputLine
                }
            }
        }
        catch {
            Write-Verbose "Không thể đọc tệp: $($file.FullName). Lỗi: $_"
        }
    }
}

# Sau khi quét xong, xuất kết quả vào file
if ($results.Count -gt 0) {
    $results | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host "`n[*] Quét hoàn tất. Kết quả đã được lưu vào file: $OutputFile" -ForegroundColor Yellow
} else {
    Write-Host "`n[-] Quét hoàn tất. Không tìm thấy kết quả nào theo từ khóa đã chỉ định." -ForegroundColor Red
}
