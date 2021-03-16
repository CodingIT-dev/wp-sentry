<?php

namespace Zeek\WpSentry;

use Sentry;
use Sentry\ClientBuilder;
use Sentry\Event;
use Sentry\SentrySdk;
use Sentry\State\Hub;
use Sentry\State\Scope;
use Zeek\Modernity\Patterns\Singleton;

class WpSentry extends Singleton {

	private const SDK_IDENTIFIER = 'sentry.php.wp-sentry-integration';
	private const SDK_VERSION = '4.2.0';

	private $client;
	private $sentryDsn;

	private $coreExclusions = [
		'Parameter 1 to wp_default_scripts() expected to be a reference, value given',
		'Parameter 1 to wp_default_styles() expected to be a reference, value given',
		'Parameter 1 to wp_default_packages() expected to be a reference, value given',
		'session_start(): Cannot start session when headers already sent',
	];

	protected function __construct() {
		$this->initSentryClient();
	}

	public function captureException( $exception ) {
		Sentry\captureException( $exception );
	}

	private function get_dsn() : ?string {
		$this->sentryDsn = get_env_value( 'SENTRY_DSN' );

		if ( empty( $this->sentryDsn ) ) {
			$this->sentryDsn = get_env_value( 'SENTRY_URL' );
		}

		if ( empty( $this->sentryDsn ) ) {
			$this->sentryDsn = E_ALL & ~E_NOTICE & ~E_WARNING;
		}

		return $this->sentryDsn;
	}

	private function get_default_options() : array {
		$options = [
			'dsn'         => $this->get_dsn(),
			'prefixes'    => [ ABSPATH ],
			'environment' => get_env_value( 'ENVIRONMENT' ),
		];

		$sentryErrorLevel = get_env_value( 'SENTRY_ERROR_LEVEL' );
		if ( ! empty( $sentryErrorLevel ) ) {
			$options['error_types'] = $sentryErrorLevel;
		}

		$options['in_app_exclude'] = [
			ABSPATH . 'wp-admin',
			ABSPATH . 'wp-includes',
		];

		$options['before_send'] = function ( Event $event ) : ?Event {
			$excludeEvents = array_merge( $this->coreExclusions, get_env_value( 'SENTRY_EXCLUDE_EVENTS' ) ?? [] );

			// Errors always get reported
			if ( (string) $event->getLevel() === 'error' ) {
				return $event;
			}

			// perform filtering here
			$eventLabel = $event->getExceptions()[0]->getValue();

			foreach ( $excludeEvents as $excludeEvent ) {
				if ( $eventLabel === $excludeEvent ) {
					return null;
				}
			}

			return $event;
		};

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
