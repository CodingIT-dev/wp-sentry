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
		$this->dsn = $this->get_dsn();

		if ( empty( $this->dsn ) ) {
			return;
		}

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

		return $this->sentryDsn;
	}

	private function errorTypes() {
		$errorTypes = get_env_value( 'SENTRY_ERROR_TYPES' );

		if ( empty( $errorTypes ) ) {
			$errorTypes = E_ALL & ~E_NOTICE & ~E_WARNING;
		}

		return $errorTypes;
	}

	private function get_default_options() : array {
		$options = [
			'dsn'         => $this->sentryDsn,
			'prefixes'    => [ ABSPATH ],
			'environment' => get_env_value( 'ENVIRONMENT' ),
			'error_types' => $this->errorTypes()
		];

		$options['in_app_exclude'] = [
			ABSPATH . 'wp-admin',
			ABSPATH . 'wp-includes',
		];

		$options['before_send'] = function ( Event $event ) : ?Event {
			$excludeEvents = array_merge( $this->coreExclusions, get_env_value( 'SENTRY_EXCLUDE_EVENTS' ) ?? [] );

			/*
			 *   Errors always get reported
			 *   Fatal errors always get reported
			 *   Everything else is configurable
			 *   SENTRY_REPORTED_LEVELS should be an array of Sentry\Severity constants:
			 *   [
			 *       'debug',
			 *       'info',
			 *       'warning',
			 *       'error',
			 *       'fatal',
			 *   ]
			 */

			$reportedLevels = get_env_value( 'SENTRY_REPORTED_LEVELS' ) ??
            [
                Sentry\Severity::ERROR,
                Sentry\Severity::FATAL,
            ];

			if ( in_array( (string) $event->getLevel(), $reportedLevels) ) {
				return $event;
			}

			/*
			 * SENTRY_EXCLUDE_PATHS should be an array of paths to exclude from reporting. Paths start from the root of the site.
			 * Always include trailing and ending slashes
			 * Example:
			 * [
			 *    '/wp-content/plugins/',
			 *    '/wp-content/plugins/akismet/',
			 * ]
			 */

			$excludedPaths = get_env_value( 'SENTRY_EXCLUDE_PATHS' ) ?? [];

			foreach ($excludedPaths as $excludedPath) {
				foreach(  $event->getExceptions() as $exception ) {
					foreach($exception->getStacktrace()->getFrames() as $frame) {
						$absoluteFilePath = $frame->getFile();
						if (str_starts_with($absoluteFilePath, $excludedPath)) {
							return null;
						}
					}
				}
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
