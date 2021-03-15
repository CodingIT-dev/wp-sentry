<?php

namespace Zeek\WpSentry;

/**
 * Helper function to check for an environmental variable in a variety of places:
 * - $_ENV (for setting via .env.php files)
 * - Constant (for setting via a define() call)
 * - Filter, utilizing a passed in filter
 *
 * @param      $key
 *
 * @return mixed|null
 */
function get_env_value( $key ) {
	if ( ! empty( $_ENV[ $key ] ) ) {
		return $_ENV[ $key ];
	}

	if ( defined( $key ) ) {
		return constant( $key );
	}

	return null;
}
