<?php
// /api/upload_lelet.php — helyi mentés + feldolgozási sorba állítás (NINCS azonnali backoffice hívás)
declare(strict_types=1);

// --- CORS (ha a feed/app más domainről jön) ---
$origin = $_SERVER['HTTP_ORIGIN'] ?? '*';
header('Access-Control-Allow-Origin: ' . $origin);
header('Vary: Origin');
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

header('Content-Type: application/json; charset=utf-8');

define('MAX_MB', 10);
$BASE        = __DIR__;
$UPLOAD_BASE = $BASE . '/uploads/leletek'; // végleges hely
$QUEUE_DIR   = $BASE . '/queue';           // feldolgozási sor (JSON jobok)
$ALLOWED_EXT  = ['jpg','jpeg','png'];
$ALLOWED_MIME = ['image/jpeg','image/png'];

// ---- util ----
function jerr(int $code, string $msg, array $extra=[]): void {
  http_response_code($code);
  echo json_encode(['status'=>'error','message'=>$msg] + $extra, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
  exit;
}
function jins(array $data=[]): void {
  echo json_encode(['status'=>'success'] + $data, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
  exit;
}
function ensure_dir(string $p): bool { return is_dir($p) || @mkdir($p,0755,true); }
function ext_from_name(string $n): string { return strtolower(pathinfo($n, PATHINFO_EXTENSION) ?: ''); }
function detect_mime(string $path): string {
  $fi = finfo_open(FILEINFO_MIME_TYPE);
  $m  = $fi ? finfo_file($fi,$path) : null;
  if ($fi) finfo_close($fi);
  return $m ?: 'application/octet-stream';
}
function exif_autorotate(string $path): void {
  if (!function_exists('imagecreatefromjpeg')) return;
  $mime = detect_mime($path);
  if ($mime !== 'image/jpeg') return;
  $exif = @exif_read_data($path);
  if (!$exif || empty($exif['Orientation'])) return;
  $img = @imagecreatefromjpeg($path);
  if (!$img) return;
  $ang = 0;
  switch ((int)$exif['Orientation']) {
    case 3: $ang = 180; break;
    case 6: $ang = -90; break;
    case 8: $ang = 90; break;
  }
  if ($ang !== 0) {
    $rot = @imagerotate($img, $ang, 0);
    if ($rot) { imagejpeg($rot, $path, 90); imagedestroy($rot); imagedestroy($img); return; }
  }
  imagedestroy($img);
}
function downscale_if_needed(string $path, int $maxSide=3000): void {
  if (!function_exists('getimagesize')) return;
  [$w,$h] = @getimagesize($path) ?: [0,0];
  if ($w===0 || $h===0) return;
  $scale = max($w,$h)/$maxSide;
  if ($scale <= 1.0) return;
  $nw = (int)round($w/$scale); $nh = (int)round($h/$scale);
  $mime = detect_mime($path);
  if ($mime === 'image/jpeg') {
    $src = @imagecreatefromjpeg($path); if(!$src) return;
    $dst = imagecreatetruecolor($nw,$nh);
    imagecopyresampled($dst,$src,0,0,0,0,$nw,$nh,$w,$h);
    imagejpeg($dst,$path,85);
    imagedestroy($src); imagedestroy($dst);
  } elseif ($mime === 'image/png') {
    $src = @imagecreatefrompng($path); if(!$src) return;
    $dst = imagecreatetruecolor($nw,$nh);
    imagealphablending($dst,false); imagesavealpha($dst,true);
    imagecopyresampled($dst,$src,0,0,0,0,$nw,$nh,$w,$h);
    imagepng($dst,$path,7);
    imagedestroy($src); imagedestroy($dst);
  }
}

// ---- only POST ----
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  header('Allow: POST, OPTIONS');
  jerr(405, 'Csak POST engedélyezett');
}

// --- Kötelező token alapú védelem ---
// A várt token vagy az UPLOAD_API_TOKEN környezeti változóból jön,
// vagy az alábbi konstansból (cseréld le biztonságos értékre!).
// TODO: később tedd környezeti változóba (UPLOAD_API_TOKEN)
$EXPECTED_TOKEN = 'ibio_2025_Ae7f1C9xP2kQ8rV4tL6mZ3hB9sN5dT1gY4uE7wJ2qX6pC3jV9lK5rS1';

// Token kiolvasása: Authorization: Bearer <token> vagy ?token=... / POST token
$token = '';
$auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
if ($auth && preg_match('/^\s*Bearer\s+(.+)$/i', $auth, $m)) {
  $token = trim($m[1]);
} elseif (isset($_POST['token'])) {
  $token = (string)$_POST['token'];
} elseif (isset($_GET['token'])) {
  $token = (string)$_GET['token'];
}

if ($token === '' || !is_string($EXPECTED_TOKEN) || $EXPECTED_TOKEN === '' || !hash_equals($EXPECTED_TOKEN, $token)) {
  jerr(401, 'Jogosulatlan: érvénytelen vagy hiányzó token');
}

$post_id = isset($_POST['post_id']) ? trim((string)$_POST['post_id']) : '';
if ($post_id === '' || !ctype_digit($post_id)) jerr(400, 'Hiányzó vagy érvénytelen post_id');
$item_id = isset($_POST['item_id']) ? trim((string)$_POST['item_id']) : '';

// első feltöltött fájl
$fileInfo = null; $fieldName = null;
foreach ($_FILES as $k=>$info) { if (!empty($info['tmp_name'])) { $fileInfo = $info; $fieldName = $k; break; } }
if (!$fileInfo) jerr(400, 'Nem érkezett fájl');

if (!empty($fileInfo['error']) && $fileInfo['error'] !== UPLOAD_ERR_OK) jerr(400, 'Feltöltési hiba ('.$fileInfo['error'].')');
if ($fileInfo['size'] > MAX_MB*1024*1024) jerr(413, 'Túl nagy fájl (max '.MAX_MB.' MB)');

$mime = detect_mime($fileInfo['tmp_name']);
if (!in_array($mime, $ALLOWED_MIME, true)) jerr(400, 'Nem engedélyezett MIME: '.$mime);

$ext = ext_from_name($fileInfo['name']);
if (!in_array($ext, $ALLOWED_EXT, true)) {
  $ext = ($mime==='image/png') ? 'png' : (($mime==='image/jpeg') ? 'jpg' : '');
  if ($ext === '') jerr(400, 'Nem támogatott kiterjesztés');
}

if (!ensure_dir($UPLOAD_BASE)) jerr(500, 'Célmappa nem hozható létre');
if (!ensure_dir($QUEUE_DIR))   jerr(500, 'Queue mappa nem hozható létre');

$targetRel = $post_id . '.' . $ext;
$targetAbs = rtrim($UPLOAD_BASE,'/').'/'.$targetRel;

if (!@move_uploaded_file($fileInfo['tmp_name'], $targetAbs)) jerr(500, 'Mentés sikertelen');

// EXIF autorotate + downscale
@exif_autorotate($targetAbs);
@downscale_if_needed($targetAbs, 3000);

@chmod($targetAbs, 0644);
$sha = @hash_file('sha256', $targetAbs) ?: null;

// job JSON queue-ba
$job = [
  'type'       => 'process_lelet',
  'post_id'    => (int)$post_id,
  'item_id'    => $item_id,
  'path_rel'   => 'uploads/leletek/'.$targetRel,
  'mime'       => $mime,
  'size'       => (int)$fileInfo['size'],
  'sha256'     => $sha,
  'created_at' => gmdate('c'),
];
$jobId   = $post_id . '-' . gmdate('Ymd\THis\Z');
$jobFile = rtrim($QUEUE_DIR,'/').'/'.$jobId.'.json';
if (@file_put_contents($jobFile, json_encode($job, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)) === false) {
  jerr(500, 'Job írása sikertelen');
}
@chmod($jobFile, 0644);

// válasz
jins([
  'file' => [
    'rel'    => $job['path_rel'],
    'mime'   => $mime,
    'size'   => (int)$fileInfo['size'],
    'sha256' => $sha
  ],
  'job' => [
    'queued'  => true,
    'id'      => $jobId,
    'item_id' => $item_id
  ]
]);