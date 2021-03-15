<?php

namespace Zeek\WpSentry;

use Sentry\ClientBuilder;
use Sentry\SentrySdk;
use Sentry\State\Hub;
use Sentry\State\Scope;
use Zeek\Modernity\Patterns\Singleton;

class WpSentry extends Singleton {

	public const SENTRY_ERROR_TYPES = 'SENTRY_ERROR_TYPES';

	private const SDK_IDENTIFIER = 'sentry.php.wp-sentry-integration';
	private const SDK_VERSION = '4.2.0';

	private $client;
	private $sentryDsn;

	protected function __construct() {
		$this->initSentryClient();
	}

	private function get_dsn() : ?string {
		$this->sentryDsn = get_env_value( 'SENTRY_DSN' );

		if ( empty( $sentryDsn ) ) {
			$this->sentryDsn = get_env_value( 'SENTRY_URL' );
		}

		return $this->sentryDsn;
	}

	private function get_default_options() : array {
		$options = [
			'dsn'              => $this->get_dsn(),
			'prefixes'         => [ ABSPATH ],
			'environment'      => get_env_value( 'ENVIRONMENT' ),
			'send_default_pii' => defined( 'WP_SENTRY_SEND_DEFAULT_PII' ) ? WP_SENTRY_SEND_DEFAULT_PII : false,
		];

		if ( get_env_value( self::SENTRY_ERROR_TYPES ) ) {
			$options['error_types'] = get_env_value( self::SENTRY_ERROR_TYPES );
		}

		$options['in_app_exclude'] = [
			ABSPATH . 'wp-admin',
			ABSPATH . 'wp-includes',
		];

		// @todo add paths to exclude

		return $options;
	}

	private function initSentryClient() {
		$clientBuilder = ClientBuilder::create( $this->get_default_options() );

		$clientBuilder->setSdkIdentifier( self::SDK_IDENTIFIER );
		$clientBuilder->setSdkVersion( self::SDK_VERSION );

		$hub = new Hub( $this->client = $clientBuilder->getClient() );

		$hub->configureScope( function ( Scope $scope ) {
			foreach ( $this->tags() as $tag => $value ) {
				$scope->setTag( $tag, $value );
			}
		} );

		SentrySdk::setCurrentHub( $hub );

		$this->client = SentrySdk::getCurrentHub();
	}

	private function tags() : array {
		return [
			'wordpress' => get_bloginfo( 'version' ),
			'language'  => get_bloginfo( 'language' ),
			'php'       => phpversion(),
		];
	}
}
