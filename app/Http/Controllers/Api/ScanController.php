<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use App\Services\HeaderScannerService; 
use App\Services\SSLScannerService;   

class ScanController extends Controller
{
    public function scan(Request $request)
    {
        $request->validate(['url' => 'required|url']);
        $url = $request->input('url');

        try {
            $host = parse_url($url, PHP_URL_HOST);

            // Call the HTTP response
            $httpResponse = Http::timeout(10)->get($url);
            
            // Use the HeaderScannerService and SSLScannerService properly
            $headers = HeaderScannerService::analyzeHeaders($url);
            $ssl = SSLScannerService::analyzeSSL($url);

            // Call Python script for full scan
            // check python requirements and packages
            $vulnScan = shell_exec("python3 scripts/vuln_scan.py " . escapeshellarg($url));
            $vulns = json_decode($vulnScan, true);

            // Return the scan results in JSON format
            return response()->json([
                'status' => $httpResponse->successful() ? 'online' : 'offline',
                'ssl' => $ssl,
                'headers' => $headers['security'],
                'server' => $headers['server'],
                'powered_by' => $headers['powered_by'],
                'vulnerabilities' => $vulns,
            ]);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Scan failed: ' . $e->getMessage()], 500);
        }
    }
}
