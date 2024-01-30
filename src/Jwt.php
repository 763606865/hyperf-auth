<?php

declare(strict_types=1);

namespace Junlin\HyperfAuth;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;

class Jwt
{
    public function __construct(protected string $key, protected $algo = new Sha256(), protected string $identify = '4890g23a12f', protected array $config = [])
    {
    }

    /**
     * @throws \Exception
     */
    public function generate(string $user_id, int $expired = 86400, array $ext = []): string
    {
        $tokenBuilder = (new Builder(new JoseEncoder(), ChainedFormatter::default()));
        $now = new DateTimeImmutable(); // 由于内部统一使用UTC时区，所以不需要转换
        $tokenBuilder
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($now->add(new DateInterval((string)$expired)))
            ->relatedTo($user_id)
            ->identifiedBy($this->identify);

        if (!empty($this->config['app_name'])) {
            $tokenBuilder->issuedBy($this->config['app_name']);
        }

        foreach ($ext as $key => $value) {
            $tokenBuilder->withClaim($key, $value);
        }

        return $tokenBuilder->getToken($this->algo, InMemory::plainText($this->key))->toString();
    }

    public function parse(string $access_token): array
    {
        $parser = new Parser(new JoseEncoder());

        $token = $parser->parse($access_token);

        return $token->claims()->all();
    }

    /**
     * @throws \HttpInvalidParamException
     */
    public function verify(string $access_token): string
    {
        $parser = new Parser(new JoseEncoder());
        $now = new DateTimeImmutable();

        try {
            if (!$token = $parser->parse($access_token)) {
                throw new \HttpInvalidParamException('Invalid Token!');
            }
        } catch (\Throwable $exception) {
            throw new \HttpInvalidParamException($exception->getMessage());
        }

        if ($token->isExpired($now)) {
            throw new \HttpInvalidParamException('Token Expired!');
        }

        $validator = new Validator();

        if (! $validator->validate($token, new SignedWith($this->algo, InMemory::plainText($this->key)))) {
            throw new \HttpInvalidParamException('Invalid Token!');
        }

        return $token->claims()->get('sub');
    }
}
