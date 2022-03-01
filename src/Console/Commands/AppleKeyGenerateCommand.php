<?php

namespace Zhyu\Socialite\Console\Commands;

use DateTimeImmutable;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Validator;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;

class AppleKeyGenerateCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'socialite:apple {--refresh : refresh secret}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generate the client secret for apple sign in';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     */
    public function handle()
    {
        if(!$this->option('refresh')){
            self::setup();
        }else{
            self::generateAppleClientSecret();
        }
    }

    /**
     * Function to generate apple client secret
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function setup()
    {
        $team_id = $this->ask('Please enter Team Id ');
        $key_id = $this->ask('Please enter Key Id ');
        $client_id = $this->ask('Please enter Client Id ');
        $auth_key = $this->anticipate('Please enter Auth Key ', ['AuthKey_'.$key_id.'.p8'], 'AuthKey_'.$key_id.'.p8');
        $callback_url = $this->ask('Please enter Redirect Uri', config('app.url').'/oauth/apple/callback');
        $refresh_token_interval_days = $this->ask('Please enter client secret refresh seconds(days)', 180);

        config([
            'services.apple.redirect' => trim($callback_url),
            'services.apple.key_id' => trim($key_id),
            'services.apple.team_id' => trim($team_id),
            'services.apple.auth_key' => trim($auth_key),
            'services.apple.client_id' => trim($client_id),
            'services.apple.refresh_token_interval_days' => trim($refresh_token_interval_days),
        ]);

        $client_secret = self::generateAppleClientSecret(false);

        if(!empty($client_secret)) {
            $env_vars = [
                'APPLE_REDIRECT_URI' => $callback_url,
                'APPLE_KEY_ID' => $key_id,
                'APPLE_TEAM_ID' => $team_id,
                'APPLE_AUTH_KEY' => $auth_key,
                'APPLE_CLIENT_ID' => $client_id,
                'APPLE_CLIENT_SECRET' => $client_secret,
                'APPLE_REFRESH_TOKEN_INTERVAL_DAYS' => $refresh_token_interval_days,
            ];

            self::writeEnv($env_vars);
        }
    }

    /**
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    private function generateAppleClientSecret($refresh=true)
    {
        $validator = Validator::make(config('services.apple'), [
            'redirect' => 'required|url',
            'key_id' => 'required',
            'team_id' => 'required',
            'auth_key' => 'required',
            'client_id' => 'required',
            'refresh_token_interval_days' => 'required|numeric',
        ]);

        if ($validator->fails()) {
            foreach ($validator->errors()->all() as $error)
            {
                $this->error($error);
            }
            return null;
        }

        $exists = Storage::disk('local')->exists(config('services.apple.auth_key'));

        if($exists){
            $privateKeyFile = Storage::disk('local')->get(config('services.apple.auth_key'));

            try{
                $config = Configuration::forSymmetricSigner(new Sha256(new MultibyteStringConverter()), InMemory::plainText($privateKeyFile));

                $now   = new DateTimeImmutable();

                $token = $config->builder()
                    //the issuer (iss claim)
                    ->issuedBy(config('services.apple.team_id'))
                    //the audience (aud claim)
                    ->permittedFor('https://appleid.apple.com')
                    //token was issue (iat claim)
                    ->issuedAt($now)
                    //the expiration time of the token (exp claim)
                    ->expiresAt($now->modify("+" . config('services.apple.refresh_token_interval_days') . " day"))
                    //title
                    ->relatedTo(config('services.apple.client_id'))
                    ->withHeader('kid', config('services.apple.key_id'))
                    ->withHeader('type', 'JWT')
                    ->withHeader('alg', 'ES256')
                    ->getToken($config->signer(), $config->signingKey());
                    //Generate a new token


                $client_secret = $token->toString();

                if(!$refresh)
                {
                    return $client_secret;
                }else{
                    self::writeEnv(['APPLE_CLIENT_SECRET' => $client_secret]);
                }
            }catch (\Exception $exception){
                $this->error($exception->getMessage());
            }
        }else {

            $this->error(config('services.apple.auth_key').' - '.'File not found in the local driver path('.config("filesystems.disks.local.root").')');

        }
    }

    /**
     * Write Env
     *
     * @param array $env_vars
     */
    private function writeEnv($env_vars)
    {
        foreach($env_vars as $env_key => $env_val){
            self::setEnv($env_key, $env_val);
        }
        self::setEnv('APPLE_CLIENT_SECRET_UPDATED_AT', time() - 86400);
        Artisan::call('config:clear');
    }

    /**
     * Set ENV
     *
     * @return mixed
     */
    public function setEnv($key, $value)
    {
        $envFilePath = app()->environmentFilePath();
        $contents = file_get_contents($envFilePath);

        if ($oldValue = $this->getOldValue($contents, $key)) {
            $contents = str_replace("{$key}={$oldValue}", "{$key}={$value}", $contents);
            $this->writeFile($envFilePath, $contents);

            return $this->info("Environment variable with key '{$key}' has been changed from '{$oldValue}' to '{$value}'");
        }

        $contents = $contents . "\n{$key}={$value}";
        $this->writeFile($envFilePath, $contents);

        return $this->info("Environment variable with key '{$key}' has been set to '{$value}'");
    }

    /**
     * Overwrite the contents of a file.
     *
     * @param string $path
     * @param string $contents
     * @return boolean
     */
    protected function writeFile(string $path, string $contents): bool
    {
        $file = fopen($path, 'w');
        fwrite($file, $contents);

        return fclose($file);
    }

    /**
     * Get the old value from an environment file.
     *
     * @param string $envFile
     * @param string $key
     * @return string
     */
    protected function getOldValue(string $envFile, string $key): string
    {
        preg_match("/^{$key}=[^\r\n]*/m", $envFile, $matches);

        if (count($matches)) {
            return substr($matches[0], strlen($key) + 1);
        }

        return '';
    }

    /**
     * Determine which key and value is from this command.
     *
     * @return array
     */
    protected function getKeyValue(): array
    {
        $key = $this->argument('key');
        $value = $this->argument('value');

        if (! $value) {
            $parts = explode('=', $key, 2);
            if (count($parts) !== 2) {
                throw new InvalidArgumentException('No value was set');
            }
            $key = $parts[0];
            $value = $parts[1];
        }

        if (! $this->isValidKey($key)) {
            throw new InvalidArgumentException('Invalid argument key');
        }

        if (! is_bool(strpos($value, ' '))) {
            $value = '"' . $value . '"';
        }

        return [strtoupper($key), $value];
    }

    /**
     * Check if variable key is validate.
     *
     * @param string $key
     * @return boolean
     */
    protected function isValidKey(string $key): bool
    {
        if (str_contains($key, '=')) {
            throw new InvalidArgumentException("Environment key should not contain '='");
        }

        if (!preg_match('/^[a-zA-Z_]+$/', $key)) {
            throw new InvalidArgumentException('Invalid environment key. Only use letters and underscores');
        }

        return true;
    }
}