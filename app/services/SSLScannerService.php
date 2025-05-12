<?php

namespace App\Services;

class SSLScannerService
{
    public static function analyzeSSL($url)
    {
        // Check SSL certificate info using OpenSSL
        $parsedUrl = parse_url($url);
        $host = $parsedUrl['host'];
        
        $sslDetails = stream_context_create(["ssl" => ["capture_peer_cert" => true]]);
        $read = stream_socket_client("ssl://$host:443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $sslDetails);
        $params = stream_context_get_params($read);
        
        $certificate = $params['options']['ssl']['peer_certificate'];
        $validFrom = date('Y-m-d', openssl_x509_parse($certificate)['validFrom_time_t']);
        $validTo = date('Y-m-d', openssl_x509_parse($certificate)['validTo_time_t']);
        $issuer = openssl_x509_parse($certificate)['issuer'];
        
        return [
            'valid_from' => $validFrom,
            'valid_to' => $validTo,
            'issuer' => implode(", ", $issuer)
        ];
    }
}
