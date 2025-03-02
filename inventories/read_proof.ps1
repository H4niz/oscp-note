# Thiết lập các tệp cần tìm
$filesToFind = @("proof.txt", "local.txt")

# Thiết lập thư mục gốc để quét (mặc định là C:\, có thể thay đổi nếu cần)
$searchRoot = "C:\"

# Tìm và đọc nội dung các tệp
foreach ($file in $filesToFind) {
    Write-Host "`nĐang tìm: $file ..."
    
    # Tìm tất cả các tệp có tên tương ứng
    $foundFiles = Get-ChildItem -Path $searchRoot -Recurse -Filter $file -ErrorAction SilentlyContinue

    if ($foundFiles) {
        foreach ($foundFile in $foundFiles) {
            Write-Host "`n[+] Đã tìm thấy: $($foundFile.FullName)"
            Write-Host "`n--- Nội dung tệp ---"
            Get-Content -Path $foundFile.FullName -ErrorAction SilentlyContinue
            Write-Host "`n----------------------"
        }
    } else {
        Write-Host "[-] Không tìm thấy tệp $file nào."
    }
}
