<?php


namespace Ingenerator\OIDCTokenVerifier;


class TokenConstraintFailureException extends \UnexpectedValueException
{

    /**
     * TokenConstraintFailureException constructor.
     *
     * @param string[] $failed_constraint_types
     */
    public function __construct(array $failed_constraint_types)
    {
        sort($failed_constraint_types);
        parent::__construct(
            sprintf(
                'Token did not match constraints: [%s]',
                implode(', ', $failed_constraint_types)
            )
        );
    }

}
