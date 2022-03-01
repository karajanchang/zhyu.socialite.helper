<?php

namespace Zhyu\Socialite;

use Zhyu\Socialite\Console\Commands\AppleKeyGenerateCommand;
use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Contracts\Factory;

class AppleHelperServiceProvider extends ServiceProvider
{
    protected $commands = [
        AppleKeyGenerateCommand::class,
    ];

    public function boot()
    {
        $this->bootAppleProvide();
    }

    public function register()
    {
        $this->registerAppleScheduler();
    }

    private function bootAppleProvide()
    {
        $this->commands($this->commands);
    }

    private function registerAppleScheduler()
    {
        $this->app->singleton('zhyu.socialite.console.kernel', function($app) {
            $dispatcher = $app->make(\Illuminate\Contracts\Events\Dispatcher::class);
            return new \Zhyu\Socialite\Console\Kernel($app, $dispatcher);
        });

        $this->app->make('zhyu.socialite.console.kernel');
    }

}