# Builds dpi_simple, dpi_mt and unit_tests into the build folder using g++.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
New-Item -ItemType Directory -Force build | Out-Null
$core = Get-ChildItem src\*.cpp | Where-Object { $_.Name -notlike 'main_*' } | ForEach-Object { "src/$($_.Name)" }
$flags = '-std=c++17', '-O2', '-Wall', '-Wextra', '-static', '-pthread', '-I', 'include'
$programs = [ordered]@{ dpi_simple = 'src/main_simple.cpp'; dpi_mt = 'src/main_mt.cpp'; unit_tests = 'tests/unit_tests.cpp' }
foreach ($name in $programs.Keys) {
    Write-Host "Building $name..."
    & g++ @flags -o "build/$name.exe" $programs[$name] @core
    if ($LASTEXITCODE -ne 0) { throw "Build of $name failed" }
}
Write-Host 'Done. Programs are in the build folder.'
