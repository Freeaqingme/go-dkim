package dkim

import (
	//"fmt"
	"strings"
	"testing"
	"time"

	"fmt"
	"github.com/stretchr/testify/assert"
)

const (
	privKey = `-----BEGIN RSA PRIVATE KEY-----
	MIICXQIBAAKBgQDNUXO+Qsl1tw+GjrqFajz0ERSEUs1FHSL/+udZRWn1Atw8gz0+
tcGqhWChBDeU9gY5sKLEAZnX3FjC/T/IbqeiSM68kS5vLkzRI84eiJrm3+IieUqI
IicsO+WYxQs+JgVx5XhpPjX4SQjHtwEC2xKkWnEv+VPgO1JWdooURcSC6QIDAQAB
AoGAM9exRgVPIS4L+Ynohu+AXJBDgfX2ZtEomUIdUGk6i+cg/RaWTFNQh2IOOBn8
ftxwTfjP4HYXBm5Y60NO66klIlzm6ci303IePmjaj8tXQiriaVA0j4hmW+xgnqQX
PubFzfnR2eWLSOGChrNFbd3YABC+qttqT6vT0KpFyLdn49ECQQD3zYCpgelb0EBo
gc5BVGkbArcknhPwO39coPqKM4csu6cgI489XpF7iMh77nBTIiy6dsDdRYXZM3bq
ELTv6K4/AkEA1BwsIZG51W5DRWaKeobykQIB6FqHLW+Zhedw7BnxS8OflYAcSWi4
uGhq0DPojmhsmUC8jUeLe79CllZNP3LU1wJBAIZcoCnI7g5Bcdr4nyxfJ4pkw4cQ
S4FT0XAZPR/YZrADo8/SWCWPdFTGSuaf17nL6vLD1zljK/skY5LwshrvUCMCQQDM
MY7ehj6DVFHYlt2LFSyhInCZscTencgK24KfGF5t1JZlwt34YaMqjAMACmi/55Fc
e7DIxW5nI/nDZrOY+EAjAkA3BHUx3PeXkXJnXjlh7nGZmk/v8tB5fiofAwfXNfL7
bz0ZrT2Caz995Dpjommh5aMpCJvUGsrYCG6/Pbha9NXl
-----END RSA PRIVATE KEY-----`

	pubKey = `MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDNUXO+Qsl1tw+GjrqFajz0ERSE
Us1FHSL/+udZRWn1Atw8gz0+tcGqhWChBDeU9gY5sKLEAZnX3FjC/T/IbqeiSM68
kS5vLkzRI84eiJrm3+IieUqIIicsO+WYxQs+JgVx5XhpPjX4SQjHtwEC2xKkWnEv
+VPgO1JWdooURcSC6QIDAQAB`

	domain = "tmail.io"

	selector = "test"
)

var emailBase = "Received: (qmail 28277 invoked from network); 1 May 2015 09:43:37 -0000" + CRLF +
	"Received: (qmail 21323 invoked from network); 1 May 2015 09:48:39 -0000" + CRLF +
	"Received: from mail483.ha.ovh.net (b6.ovh.net [213.186.33.56])" + CRLF +
	" by mo51.mail-out.ovh.net (Postfix) with SMTP id A6E22FF8934" + CRLF +
	" for <toorop@toorop.fr>; Mon,  4 May 2015 14:00:47 +0200 (CEST)" + CRLF +
	"MIME-Version: 1.0" + CRLF +
	"Date: Fri, 1 May 2015 11:48:37 +0200" + CRLF +
	"Message-ID: <CADu37kTXBeNkJdXc4bSF8DbJnXmNjkLbnswK6GzG_2yn7U7P6w@tmail.io>" + CRLF +
	"Subject: Test DKIM" + CRLF +
	"From: =?UTF-8?Q?St=C3=A9phane_Depierrepont?= <toorop@tmail.io>" + CRLF +
	"To: =?UTF-8?Q?St=C3=A9phane_Depierrepont?= <toorop@toorop.fr>" + CRLF +
	"Content-Type: text/plain; charset=UTF-8" + CRLF + CRLF +
	"Hello world" + CRLF +
	"line with trailing space         " + CRLF +
	"line with           space         " + CRLF +
	"-- " + CRLF +
	"Toorop" + CRLF + CRLF + CRLF + CRLF + CRLF + CRLF

var emailBaseNoFrom = "Received: (qmail 28277 invoked from network); 1 May 2015 09:43:37 -0000" + CRLF +
	"Received: (qmail 21323 invoked from network); 1 May 2015 09:48:39 -0000" + CRLF +
	"Received: from mail483.ha.ovh.net (b6.ovh.net [213.186.33.56])" + CRLF +
	" by mo51.mail-out.ovh.net (Postfix) with SMTP id A6E22FF8934" + CRLF +
	" for <toorop@toorop.fr>; Mon,  4 May 2015 14:00:47 +0200 (CEST)" + CRLF +
	"MIME-Version: 1.0" + CRLF +
	"Date: Fri, 1 May 2015 11:48:37 +0200" + CRLF +
	"Message-ID: <CADu37kTXBeNkJdXc4bSF8DbJnXmNjkLbnswK6GzG_2yn7U7P6w@tmail.io>" + CRLF +
	"Subject: Test DKIM" + CRLF +
	"To: =?UTF-8?Q?St=C3=A9phane_Depierrepont?= <toorop@toorop.fr>" + CRLF +
	"Content-Type: text/plain; charset=UTF-8" + CRLF + CRLF +
	"Hello world" + CRLF +
	"line with trailing space         " + CRLF +
	"line with           space         " + CRLF +
	"-- " + CRLF +
	"Toorop" + CRLF + CRLF + CRLF + CRLF + CRLF + CRLF

var headerSimple = "From: =?UTF-8?Q?St=C3=A9phane_Depierrepont?= <toorop@tmail.io>" + CRLF +
	"Date: Fri, 1 May 2015 11:48:37 +0200" + CRLF +
	"MIME-Version: 1.0" + CRLF +
	"Received: from mail483.ha.ovh.net (b6.ovh.net [213.186.33.56])" + CRLF +
	" by mo51.mail-out.ovh.net (Postfix) with SMTP id A6E22FF8934" + CRLF +
	" for <toorop@toorop.fr>; Mon,  4 May 2015 14:00:47 +0200 (CEST)" + CRLF +
	"Received: (qmail 21323 invoked from network); 1 May 2015 09:48:39 -0000" + CRLF

var headerRelaxed = "from:=?UTF-8?Q?St=C3=A9phane_Depierrepont?= <toorop@tmail.io>" + CRLF +
	"date:Fri, 1 May 2015 11:48:37 +0200" + CRLF +
	"mime-version:1.0" + CRLF +
	"received:from mail483.ha.ovh.net (b6.ovh.net [213.186.33.56]) by mo51.mail-out.ovh.net (Postfix) with SMTP id A6E22FF8934 for <toorop@toorop.fr>; Mon, 4 May 2015 14:00:47 +0200 (CEST)" + CRLF +
	"received:(qmail 21323 invoked from network); 1 May 2015 09:48:39 -0000" + CRLF

var bodySimple = "Hello world" + CRLF +
	"line with trailing space         " + CRLF +
	"line with           space         " + CRLF +
	"-- " + CRLF +
	"Toorop" + CRLF

var bodyRelaxed = "Hello world" + CRLF +
	"line with trailing space" + CRLF +
	"line with space" + CRLF +
	"--" + CRLF +
	"Toorop" + CRLF

var signedRelaxedRelaxed = "DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=relaxed/relaxed;" + CRLF +
	" s=test; d=tmail.io; h=from:date:mime-version:received:received;" + CRLF +
	" bh=4pCY+Pp2c/Wr8fDfBDWKpx3DDsr0CJfSP9H1KYxm5bA=;" + CRLF +
	" b=o0eE20jd8jYqkyxP5rqbfcoUABWZyfrL+l3e1lC0Z+b1Azyrdv+UMmx8L5F57Rhya1SNG2" + CRLF +
	" 9FnMUTwq+u1PmOmB7NwfTq5UCS9UR8wrNffI1mLUsBPFtv+jZtnHzdmR9aCo2HPfBBALC8" + CRLF +
	" jEhQcvm/RaP0aiYJtisLJ86S3k0P1WU=" + CRLF + emailBase

var signedRelaxedRelaxedLength = "DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=relaxed/relaxed;" + CRLF +
	" s=test; d=tmail.io; l=5; h=from:date:mime-version:received:received;" + CRLF +
	" bh=GF+NsyJx/iX1Yab8k4suJkMG7DBO2lGAB9F2SCY4GWk=;" + CRLF +
	" b=byhiFWd0lAM1sqD1tl8S1DZtKNqgiEZp8jrGds6RRydnZkdX9rCPeL0Q5MYWBQ/JmQrml5" + CRLF +
	" pIghLwl/EshDBmNy65O6qO8pSSGgZmM3T7SRLMloex8bnrBJ4KSYcHV46639gVEWcBOKW0" + CRLF +
	" h1djZu2jaTuxGeJzlFVtw3Arf2B93cc=" + CRLF + emailBase

var signedSimpleSimple = "DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=simple/simple;" + CRLF +
	" s=test; d=tmail.io; h=from:date:mime-version:received:received;" + CRLF +
	" bh=ZrMyJ01ZlWHPSzskR7A+4CeBDAd0m8CPny4m15ablao=;" + CRLF +
	" b=nzkqVMlEBL+6m/1AtlFzGV2tHjvfNwFmz9kUDNqphBNSvguv/8KAdqsVheBudJBDHNPrjr" + CRLF +
	" +N57+atXBQX/jng2WAlI5wpQb1TlxLfm8b7SyS1Z7WwSOI0MqaLMhIss4QEVsevaTF1d/1" + CRLF +
	" WcFzOPxn66nnn+CRKaz553tjIn1GeFQ=" + CRLF + emailBase

var signedSimpleSimpleLength = "DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=simple/simple;" + CRLF +
	" s=test; d=tmail.io; l=5; h=from:subject:date:message-id;" + CRLF +
	" bh=GF+NsyJx/iX1Yab8k4suJkMG7DBO2lGAB9F2SCY4GWk=;" + CRLF +
	" b=P4cX4WxnSytfsQ3skg3fYIRljleh2iDJidlr/GPfA4S8pTPNZj4SPhB7CJ6OcbSWwJ6Yer" + CRLF +
	" rHGEmCSEGHJPQm+P12iujJlQ784i34JsBvMC5YAMIQ0DHTNhJRHEyShg1I0B3tqArogdap" + CRLF +
	" qwWLUSFEhPTXglZVhcHIvYZA9X38iF4=" + CRLF + emailBase

var signedNoFrom = "DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=simple/simple;" + CRLF +
	" s=test; d=tmail.io; h=from:date:mime-version:received:received;" + CRLF +
	" bh=GF+NsyJx/iX1Yab8k4suJkMG7DBO2lGAB9F2SCY4GWk=;" + CRLF +
	" b=SoEhlu1Emm2ASqo8jMhz6FIf2nNHt3ouY4Av/pFFEkQ048RqUFP437ap7RbtL2wh0N3Kkm" + CRLF +
	" AKF2TcTLZ++1nalq+djU+/aP4KYQd4RWWFBjkxDzvCH4bvB1M5AGp4Qz9ldmdMQBWOvvSp" + CRLF +
	" DIpJW4XNA/uqLSswtjCYbJsSg9Ywv1o=" + CRLF + emailBaseNoFrom

var signedMissingFlag = "DKIM-Signature: v=1; q=dns/txt; c=simple/simple;" + CRLF +
	" s=test; d=tmail.io; l=5; h=from:date:mime-version:received:received;" + CRLF +
	" bh=GF+NsyJx/iX1Yab8k4suJkMG7DBO2lGAB9F2SCY4GWk=;" + CRLF +
	" b=SoEhlu1Emm2ASqo8jMhz6FIf2nNHt3ouY4Av/pFFEkQ048RqUFP437ap7RbtL2wh0N3Kkm" + CRLF +
	" AKF2TcTLZ++1nalq+djU+/aP4KYQd4RWWFBjkxDzvCH4bvB1M5AGp4Qz9ldmdMQBWOvvSp" + CRLF +
	" DIpJW4XNA/uqLSswtjCYbJsSg9Ywv1o=" + CRLF + emailBase

var signedBadAlgo = "DKIM-Signature: v=1; a=rsa-shasha; q=dns/txt; c=simple/simple;" + CRLF +
	" s=test; d=tmail.io; l=5; h=from:date:mime-version:received:received;" + CRLF +
	" bh=GF+NsyJx/iX1Yab8k4suJkMG7DBO2lGAB9F2SCY4GWk=;" + CRLF +
	" b=SoEhlu1Emm2ASqo8jMhz6FIf2nNHt3ouY4Av/pFFEkQ048RqUFP437ap7RbtL2wh0N3Kkm" + CRLF +
	" AKF2TcTLZ++1nalq+djU+/aP4KYQd4RWWFBjkxDzvCH4bvB1M5AGp4Qz9ldmdMQBWOvvSp" + CRLF +
	" DIpJW4XNA/uqLSswtjCYbJsSg9Ywv1o=" + CRLF + emailBase

var signedDouble = "DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=simple/simple;" + CRLF +
	" s=test; d=tmail.io; l=5; h=from:date:mime-version:received:received;" + CRLF +
	" bh=GF+NsyJx/iX1Yab8k4suJkMG7DBO2lGAB9F2SCY4GWk=;" + CRLF +
	" b=SoEhlu1Emm2ASqo8jMhz6FIf2nNHt3ouY4Av/pFFEkQ048RqUFP437ap7RbtL2wh0N3Kkm" + CRLF +
	" AKF2TcTLZ++1nalq+djU+/aP4KYQd4RWWFBjkxDzvCH4bvB1M5AGp4Qz9ldmdMQBWOvvSp" + CRLF +
	" DIpJW4XNA/uqLSswtjCYbJsSg9Ywv1o=" + CRLF +
	"DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=relaxed/relaxed;" + CRLF +
	" s=test; d=tmail.io; l=5; h=from:date:mime-version:received:received;" + CRLF +
	" bh=GF+NsyJx/iX1Yab8k4suJkMG7DBO2lGAB9F2SCY4GWk=;" + CRLF +
	" b=byhiFWd0lAM1sqD1tl8S1DZtKNqgiEZp8jrGds6RRydnZkdX9rCPeL0Q5MYWBQ/JmQrml5" + CRLF +
	" pIghLwl/EshDBmNy65O6qO8pSSGgZmM3T7SRLMloex8bnrBJ4KSYcHV46639gVEWcBOKW0" + CRLF +
	" h1djZu2jaTuxGeJzlFVtw3Arf2B93cc=" + CRLF + emailBase

var fromGmail = "Return-Path: toorop@gmail.com" + CRLF +
	"Delivered-To: toorop@tmail.io" + CRLF +
	"Received: tmail deliverd local d9ae3ac7c238a50a6e007d207337752eb04038ff; 21 May 2015 19:47:54 +0200" + CRLF +
	"X-Env-From: toorop@gmail.com" + CRLF +
	"Received: from 209.85.217.176 (mail-lb0-f176.google.com.) (mail-lb0-f176.google.com)" + CRLF +
	"	  by 5.196.15.145 (mail.tmail.io.) with ESMTPS; 21 May 2015 19:47:54 +0200; tmail 0.0.8" + CRLF +
	"	; 8008e7eae6f168de88db072ead2b34d0f9194cc5" + CRLF +
	"Authentication-Results: dkim=permfail body hash did not verify" + CRLF +
	"Received: by lbbqq2 with SMTP id qq2so23551469lbb.3" + CRLF +
	"        for <toorop@tmail.io>; Thu, 21 May 2015 10:43:42 -0700 (PDT)" + CRLF +
	"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;" + CRLF +
	"        d=gmail.com; s=20120113;" + CRLF +
	"        h=mime-version:date:message-id:subject:from:to:content-type;" + CRLF +
	"        bh=pwO8HiXlNND4gOHL7bTlAtJFqYruIH1x8q3dAqEw138=;" + CRLF +
	"        b=lh5rCv0Y2uh23DLUv+YsPZEmJMkhxlVRG+aeCmtJ5BpXTbSHldmNv1vbSegCx0LY9K" + CRLF +
	"         l0AEGrpce6YgBk5qRphffEOhANKEkrLesMUyI3yc9JG2J6R19mJ/NyDkT5USZZuI8DOp" + CRLF +
	"         GkRQSIPU4lrj3U27pr6+8I2lANJfINkqbkbBb69068/aPYl2DUMP5SPCFNwB01LHWKqI" + CRLF +
	"         srRDhqRYnAql+PZJVbzrue2HwBflr4ycDzhfZ+Q5BxQZt+TJtzkCUHTGtx5z9JctR93E" + CRLF +
	"         K5hUpKBN6w6GEbj1HDiMsYZOICx3XNDkny8HhFmU0nPjwbHN2C8HslOGZtDPeZWJypSG" + CRLF +
	"         Wuig==" + CRLF +
	"MIME-Version: 1.0" + CRLF +
	"X-Received: by 10.152.206.103 with SMTP id ln7mr3235525lac.40.1432230222503;" + CRLF +
	" Thu, 21 May 2015 10:43:42 -0700 (PDT)" + CRLF +
	"Received: by 10.112.162.129 with HTTP; Thu, 21 May 2015 10:43:42 -0700 (PDT)" + CRLF +
	"Date: Thu, 21 May 2015 19:43:42 +0200" + CRLF +
	"Message-ID: <CADu37kSVY5ZSq9MGjw3yXfn1eNF-hMHjWJyb87JqS4Z79Zksww@mail.gmail.com>" + CRLF +
	"Subject: Test smtpdData" + CRLF +
	"From: =?UTF-8?Q?St=C3=A9phane_Depierrepont?= <toorop@gmail.com>" + CRLF +
	"To: toorop@tmail.io" + CRLF +
	"Content-Type: text/plain; charset=UTF-8" + CRLF + CRLF +
	"Alors ?" + CRLF + CRLF +
	"-- " + CRLF +
	"Toorop" + CRLF +
	"http://www.protecmail.com" + CRLF + CRLF + CRLF

var missingHeaderMail = "Received: tmail deliverd remote 439903a23facd153908f3e17fb487962d01f4b44; 02 Jun 2015 10:00:24 +0000" + CRLF +
	"X-Env-From: toorop@toorop.fr" + CRLF +
	"Received: from 192.168.0.2 (no reverse) by 192.168.0.46 (no reverse) whith" + CRLF +
	"   SMTP; 02 Jun 2015 10:00:23 +0000; tmail 0.0.8;" + CRLF +
	"   d3c348615ef29692ca8bdacb40d0e147c977579c" + CRLF +
	"Message-ID: <1433239223.d3c348615ef29692ca8bdacb40d0e147c977579c@toorop.fr>" + CRLF +
	"Date: Thu, 21 May 2015 19:43:42 +0200" + CRLF +
	"Subject: test" + CRLF + CRLF +
	"test"

func Test_NewSigOptions(t *testing.T) {
	dkim := NewDkim()
	options := dkim.NewSigOptions()
	assert.Equal(t, "rsa-sha256", options.Algo)
	assert.Equal(t, "simple/simple", options.Canonicalization)
}

func Test_SignConfig(t *testing.T) {
	dkim := NewDkim()

	email := []byte(emailBase)
	emailToTest := append([]byte(nil), email...)
	options := dkim.NewSigOptions()
	_, err := dkim.Sign(emailToTest, options)
	assert.NotNil(t, err)
	// && err No private key
	assert.EqualError(t, err, ErrSignPrivateKeyRequired.Error())
	options.PrivateKey = []byte(privKey)
	emailToTest = append([]byte(nil), email...)
	_, err = dkim.Sign(emailToTest, options)

	// Domain
	assert.EqualError(t, err, ErrSignDomainRequired.Error())
	options.Domain = "toorop.fr"
	emailToTest = append([]byte(nil), email...)
	_, err = dkim.Sign(emailToTest, options)

	// Selector
	assert.Error(t, err, ErrSignSelectorRequired.Error())
	options.Selector = "default"
	emailToTest = append([]byte(nil), email...)
	_, err = dkim.Sign(emailToTest, options)
	assert.NoError(t, err)

	// Canonicalization
	options.Canonicalization = "simple/relaxed/simple"
	emailToTest = append([]byte(nil), email...)
	_, err = dkim.Sign(emailToTest, options)
	assert.EqualError(t, err, ErrSignBadCanonicalization.Error())

	options.Canonicalization = "simple/relax"
	emailToTest = append([]byte(nil), email...)
	_, err = dkim.Sign(emailToTest, options)
	assert.EqualError(t, err, ErrSignBadCanonicalization.Error())

	options.Canonicalization = "relaxed"
	emailToTest = append([]byte(nil), email...)
	_, err = dkim.Sign(emailToTest, options)
	assert.NoError(t, err)

	options.Canonicalization = "SiMple/relAxed"
	emailToTest = append([]byte(nil), email...)
	_, err = dkim.Sign(emailToTest, options)
	assert.NoError(t, err)

	// header
	options.Headers = []string{"toto"}
	emailToTest = append([]byte(nil), email...)
	_, err = dkim.Sign(emailToTest, options)
	assert.EqualError(t, err, ErrSignHeaderShouldContainsFrom.Error())

	options.Headers = []string{"To", "From"}
	emailToTest = append([]byte(nil), email...)
	_, err = dkim.Sign(emailToTest, options)
	assert.NoError(t, err)

}

func Test_canonicalize(t *testing.T) {
	dkim := NewDkim()

	email := []byte(emailBase)
	emailToTest := append([]byte(nil), email...)
	options := dkim.NewSigOptions()
	options.Headers = []string{"from", "date", "mime-version", "received", "received", "In-Reply-To"}
	// simple/simple
	options.Canonicalization = "simple/simple"
	header, body, err := canonicalize(emailToTest, options.Canonicalization, options.Headers)
	assert.NoError(t, err)
	assert.Equal(t, headerSimple, string(header))
	assert.Equal(t, bodySimple, string(body))

	// relaxed/relaxed
	emailToTest = append([]byte(nil), email...)
	options.Canonicalization = "relaxed/relaxed"
	header, body, err = canonicalize(emailToTest, options.Canonicalization, options.Headers)
	assert.NoError(t, err)
	assert.Equal(t, headerRelaxed, string(header))
	assert.Equal(t, bodyRelaxed, string(body))

}

func Test_Sign(t *testing.T) {
	dkim := NewDkim()

	email := []byte(emailBase)
	emailRelaxed := append([]byte(nil), email...)
	options := dkim.NewSigOptions()
	options.PrivateKey = []byte(privKey)
	options.Domain = domain
	options.Selector = selector
	//options.SignatureExpireIn = 3600
	options.Headers = []string{"from", "date", "mime-version", "received", "received", "cc"}
	options.AddSignatureTimestamp = false

	options.Canonicalization = "relaxed/relaxed"
	emailRelaxed, err := dkim.Sign(emailRelaxed, options)
	assert.NoError(t, err)
	assert.Equal(t, signedRelaxedRelaxed, string(emailRelaxed))

	options.BodyLength = 5
	emailRelaxed = append([]byte(nil), email...)
	emailRelaxed, err = dkim.Sign(emailRelaxed, options)
	assert.NoError(t, err)
	assert.Equal(t, signedRelaxedRelaxedLength, string(emailRelaxed))

	options.BodyLength = 0
	options.Canonicalization = "simple/simple"
	emailSimple := append([]byte(nil), email...)
	emailSimple, err = dkim.Sign(emailSimple, options)
	assert.Equal(t, signedSimpleSimple, string(emailSimple))

	options.Headers = []string{"from", "subject", "date", "message-id"}
	memail := []byte(missingHeaderMail)
	_, err = dkim.Sign(memail, options)
	assert.NoError(t, err)

	options.BodyLength = 5
	options.Canonicalization = "simple/simple"
	emailSimple = append([]byte(nil), email...)
	emailSimple, err = dkim.Sign(emailSimple, options)
	assert.Equal(t, signedSimpleSimpleLength, string(emailSimple))

	// options.BodyLength is way larger than email body
	options.BodyLength = 50000
	emailRelaxed = append([]byte(nil), email...)
	emailRelaxed, err = dkim.Sign(emailRelaxed, options)
	assert.NoError(t, err)
}

func Test_Verify(t *testing.T) {
	dkim := NewDkim()

	// no DKIM header
	email := []byte(emailBase)
	_, err := dkim.Verify(email)
	assert.Equal(t, ErrDkimHeaderNotFound, err)

	// No From
	email = []byte(signedNoFrom)
	_, err = dkim.Verify(email)
	assert.Equal(t, ErrVerifyBodyHash, err)

	// missing mandatory 'a' flag
	email = []byte(signedMissingFlag)
	_, err = dkim.Verify(email)
	assert.Error(t, err)
	assert.Equal(t, ErrDkimHeaderMissingRequiredTag, err)

	// missing bad algo
	email = []byte(signedBadAlgo)
	_, err = dkim.Verify(email)
	assert.Equal(t, ErrSignBadAlgo, err)

	// relaxed
	email = []byte(signedRelaxedRelaxedLength)
	_, err = dkim.Verify(email)
	assert.Equal(t, ErrTesting, err)

	// simple
	email = []byte(signedSimpleSimpleLength)
	_, err = dkim.Verify(email)
	assert.Equal(t, ErrTesting, err)

	// gmail
	email = []byte(fromGmail)
	_, err = dkim.Verify(email)
	assert.NoError(t, err)

}

var yahooIncDKIMtest = strings.Replace(`X-Apparently-To: andreser@yahoo-inc.com; Mon, 17 Aug 2015 22:49:25 +0000
Return-Path: <andreser@yahoo-inc.com>
Received-SPF: pass (domain of yahoo-inc.com designates 216.145.54.109 as permitted sender)
X-YMailISG: mjZhcf4WLDsyM65yWRfgyfO_lZT.dRW6ZkL0mQ36QKSZ1wt8
 norPyPfS_RaocAsatZMUc76bWB9uuFubtxIu.6wHOaop_IvkFzIxMpIj0qV.
 Lrx.L7iOLJ2Y5WVt6viLV7QS58O_2NzGwj3OIQL5EkGvSAZntHzX6fwew2_o
 mtpmgrO9DKSOmSxs0mI1hgXdqr2U2oqrtF9ibc4Z2cFMaZ4R1JeYcprQW9Xu
 X0YqkidSky.VEpst35uNTE.OMGZrIFHPzaKfF5GarnIJGSqhk.5NMjq_Bywg
 5LYpX9AoXaCFOQd0Tzp4raM0IUmhBRaGPPXUBbzqovVvuLdJ.clh6.kYtv_F
 5aNQtHP5cNqhPTooi1c_mZlh6phP12PMUVdx9WdfEmvVaN1Jumay.SzOtTPh
 89IA7pgAferCuLh5f_9lEkYLkFomW4SRwexAbpdfwm1R1CYprsZMQ1YhFZI3
 GinHyEiPUo48hxgTJgWIuv0oiCoDzd8exD5.u0ZW6Ztvy3UVvogbGCJ6KvXy
 7CT1iwdHcoCiGcoE9e7zEqZdH7GftkZGobaX83r3bzhhc0GVMmY29fB4BnZj
 suHtpK.Cx7vY.hJvV_R_.QH5npxcM8ptVFLgkNW6tBzqF9GnbWtr7v2ERGjn
 hewHjiEQAGbay6c19tw.3s0SEEhb0BdbxeGajeqNJhYLC8j18hRQR67oWyFF
 LON7S1cfRM2sQKVWW4K0I7KMad7FrxEi6VJdfIVD8gLMW7uhlkowqOE9rhtj
 042FEnYc7kcrvL58Bj8v9TY3Z2Nl8HXifr6dGK_Kw9HK79We3O00cdZSWASu
 R8pA_AB40d80d82.0crHu0oFFX6KFT8xkAipyIvPhK4bZz7r.NnBD1ZKq7ZF
 TpBmxt0hbxWy_Qkz1M9BrzrGbbeSAFhAyyZqoPYsWy8FN5U3jzU.ZQygaK.E
 DT18hIHBF2qN4R3JLVxA7zX1OfxL24UlPvuPaAERm9Wq4WRagcK7ysJt7.9b
 WskH.vySl_.3mtF7yBFXOR_7_aIM54djcILP_MGhqEjJVbPp12KmbQ51cD_o
 76mHVraxIkOZV0eVal8V9QwIaAbbb9caFJcySJdUSIVvojxd6fneN83jCsD.
 Df0Iz4J2pF0BYiVnY4.MIhUSZZtCjxBAK4roNSvdyVDEQdYPiJpQHoBIDCnj
 mgQCRPWOCRXaaDMnFvBzJJ7_z04R5rB3vFg65xsBN0wyeDX1veLLsMHChAbp
 8RPEQFrsqmFFrXXRODtacXX1ZOZV1tTI
X-Originating-IP: [216.145.54.109]
Authentication-Results: mta2007.corp.mail.ne1.yahoo.com  from=yahoo-inc.com; domainkeys=neutral (no sig);  from=yahoo-inc.com; dkim=pass (ok)
Received: from 127.0.0.1  (EHLO mrout4.yahoo.com) (216.145.54.109)
  by mta2007.corp.mail.ne1.yahoo.com with SMTPS; Mon, 17 Aug 2015 22:49:25 +0000
Received: from omp1017.mail.ne1.yahoo.com (omp1017.mail.ne1.yahoo.com [98.138.89.161])
	by mrout4.yahoo.com (8.14.9/8.14.9/y.out) with ESMTP id t7HMn6pT004450
	(version=TLSv1/SSLv3 cipher=DHE-RSA-CAMELLIA256-SHA bits=256 verify=NO)
	for <andreser@yahoo-inc.com>; Mon, 17 Aug 2015 15:49:06 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=yahoo-inc.com;
	s=cobra; t=1439851746;
	bh=Zg0pSZvCcMHE9S9qpkoEKeacBIM4T3Xu4TUSMEL4rXw=;
	h=Date:From:Reply-To:To:Subject;
	b=C+cq+oEeDf+21aR1gaYIeuqE9cwJBuT3leqtd1ktLtmd4R3HAWXkt8Wr18PeOicjT
	 +8IJeZ4t+D6UDq3cIHRblyK2+LRP514YDttLfNbQQ28BOlEaycS4ZbrRtwYR0/bJsJ
	 EekQ8FrwzHZQOlmrqeN4bVIAlI73X+OBynbLyDrw=
Received: (qmail 15334 invoked by uid 1000); 17 Aug 2015 22:49:06 -0000
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=yahoo-inc.com; s=ginc1024; t=1439851746; bh=Zg0pSZvCcMHE9S9qpkoEKeacBIM4T3Xu4TUSMEL4rXw=; h=Date:From:Reply-To:To:Message-ID:Subject:MIME-Version:Content-Type; b=Ut+tXUluIOFrGnFm6m0fvXuIQDIEulXFkWmj9bQSO0JN3gPiWfuh1bFhZBdnu2C4SREtTfrxHI8q5DGPjD8yg4LnxFh3HOuaf4Ttm8w72QGO1HxJCdwkNvu5W4mnFTEB8hdl2u5naE4JqjJtM291ZYIJGvxFA2J3+Snj/N2aG40=
X-YMail-OSG: G1B4VdwVM1lYA9kmxoxrGwEODiHeae6vbYVeBm754R2VWrC5KBM9pyd4ojSurOA
 q0um_rXRvGr1aqpHntt5GL5mcITy4qZFZWIBKRlGdOvQKNsKMSzsglbrG0Io._.0dI8XBQ.DNWG3
 Z5uVt9prZqJLlJG.FcGrNnYQTiX.Q0HDTID4rDKM.sA6Z_CUAPOto0IFqnA9buS5R8Rjy3xqs5qf
 krxUdQCFbVG.ML8Kl0WJfy8ZKxjg1mT7Nma.ZOA--
Received: by 98.138.105.251; Mon, 17 Aug 2015 22:49:05 +0000 
Date: Mon, 17 Aug 2015 22:49:05 +0000 (UTC)
From: Andres Erbsen <andreser@yahoo-inc.com>
Reply-To: Andres Erbsen <andreser@yahoo-inc.com>
To: Andres Erbsen Erbsen <andreser@yahoo-inc.com>
Message-ID: <408588803.6263873.1439851745104.JavaMail.yahoo@mail.yahoo.com>
Subject: end-to-end public key verification [test]
MIME-Version: 1.0
Content-Type: multipart/alternative; 
	boundary="----=_Part_6263872_19047179.1439851745102"
Content-Length: 622

------=_Part_6263872_19047179.1439851745102
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 7bit

fdsfasdfdasgawgasdgdsgadfgadsgdgadga
------=_Part_6263872_19047179.1439851745102
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: 7bit

<html><body><div style="color:#000; background-color:#fff; font-family:HelveticaNeue-Light, Helvetica Neue Light, Helvetica Neue, Helvetica, Arial, Lucida Grande, sans-serif;font-size:16px"><div id="yui_3_16_0_1_1439835732243_26145" dir="ltr">fdsfasdfdasgawgasdgdsgadfgadsgdgadga</div></div></body></html>
------=_Part_6263872_19047179.1439851745102--`, "\n", "\r\n", -1)

func TestYahooIncDKIM(t *testing.T) {
	dkim := NewDkim()
	dkim.lookupTXT = func(string) ([]string, error) {
		return []string{"v=DKIM1; g=*; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDGDd1Fz/AblN4d1haW+4B/u8PXkpd/s/JFkCPqp0Zk8xZ/SEs15fsWmj7yZwfsgi04Bs1eJhUIGf0iufHvkK5ws5XKBfbw1hYBHexopqYT5JFERYJ3slNEG5EeB04kKWpECjoMkXhDWvUJrHaBqGAz2KQ1dKAzrtKqRN2IVcDbBQIDAQAB"}, nil
	}
	_, err := dkim.Verify([]byte(yahooIncDKIMtest))
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(time.Now())
}
