package org.uqbar.peliculasmicroserviceauth.security

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.stereotype.Component
import org.uqbar.peliculasmicroserviceauth.exceptions.CredencialesInvalidasException
import java.util.*


@Component
class TokenUtils {
   @Value("\${security.secret-key}")
   lateinit var secretKey: String

   @Value("\${security.access-token-minutes}")
   var accessTokenMinutes: Int = 60

   val logger = LoggerFactory.getLogger(TokenUtils::class.java)

   fun createToken(nombre: String, password: String): String? {
      val longExpirationTime = accessTokenMinutes * 60 * 60 * 1000

      val now = Date()

      return Jwts.builder()
         .subject(nombre)
         .issuedAt(now)
         .expiration(Date(now.time + longExpirationTime))
         .claim("roles", if (nombre == "admin") "ROLE_ADMIN" else "ROLE_USER")
         .signWith(Keys.hmacShaKeyFor(secretKey.toByteArray()))
         .compact()

   }

   fun getAuthentication(token: String): UsernamePasswordAuthenticationToken {
      val secret = Keys.hmacShaKeyFor(secretKey.toByteArray())
      val claims = Jwts.parser()
         .verifyWith(secret)
         .build()
         .parseSignedClaims(token)
         .payload

      // TODO: chequear expiration a ver si se venció el token

      if (claims.subject == null) {
         throw CredencialesInvalidasException()
      }

      logger.info("Token decoded, user: " + claims.subject + " - roles: " + claims["roles"])

      return UsernamePasswordAuthenticationToken(claims.subject, null, listOf(SimpleGrantedAuthority(claims["roles"] as String)))
   }
}