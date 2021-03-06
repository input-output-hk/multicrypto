package io.iohk.multicrypto.certificates.test.data

import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.spec.PKCS8EncodedKeySpec

object ExampleCertificates {

  private val factory = CertificateFactory.getInstance("X.509")

  private def fromHex(hex: String): Array[Byte] = {
    hex
      .sliding(2, 2)
      .toArray
      .map(s => Integer.parseInt(s, 16).toByte)
  }

  def decodeX509(pem: String): X509Certificate = {
    factory
      .generateCertificate(new ByteArrayInputStream(pem.getBytes))
      .asInstanceOf[X509Certificate]
  }

  def decodePrivateKey(bytes: Array[Byte]) = {
    val keyFactory = KeyFactory.getInstance("RSA")

    val privateKeySpec = new PKCS8EncodedKeySpec(bytes)
    keyFactory.generatePrivate(privateKeySpec)
  }

  val enterpriseCA =
    """
      |-----BEGIN CERTIFICATE-----
      |MIIC1TCCAb2gAwIBAgIEXAtR6zANBgkqhkiG9w0BAQsFADAcMQswCQYDVQQGEwJI
      |SzENMAsGA1UEAwwESU9ISzAgFw0wMDEyMDgwNTA4NTlaGA8yMDYwMTIwODA1MDg1
      |OVowHDELMAkGA1UEBhMCSEsxDTALBgNVBAMMBElPSEswggEiMA0GCSqGSIb3DQEB
      |AQUAA4IBDwAwggEKAoIBAQDbkYWD2fvI/2VpXg9uqxWQ7hf5B4m0Kkld6+QKgUY8
      |FGBsX9hJBdkdvXk9EutILOtof1bXuMTRlTwBN/WOrKUfTOSi5I7A+lXUggkrTa1i
      |U+SjAmx2UZ3GSjefIFpb7e1AOyrIiiT9AY0F0QiScPF0LSZ6OzwWWYqwmkk5h7yT
      |pFtesh39vSnXZzGIxRzkAkqbDKnOQ7hQ+w+dvpgKXdU4fI2oF0Q3hNWuqepMJ3eA
      |0y9NjK3+hhGYVQBxhu2Hj4EabF9scHkg1L4zaWZ4gf42luMvbOLFy5/mF0P3wkgi
      |8YZBSpW9uOfDysvpTmQc69lPYuSEH+cxnFqLmK5f+go3AgMBAAGjHTAbMAwGA1Ud
      |EwQFMAMBAf8wCwYDVR0PBAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQBgo+sUJQcl
      |6P/5xI+ExIsvCSfZWiTiVloCUwBvdBSwNo62ZdwPMXEjSiYxu9TLZVts9uK2hlpK
      |FQd/ZN0NTxTFskKdSXgy+jUm5kIU8i6D8eupyiPfqyMv7z7g4iUOSEXToCfCcLDu
      |2MkomJilCmxJlEn+Z+QbTxxYJ3U/EgAIKj7pWAsRfHhC6j7+vNMXvOgI8dnu0mDk
      |VhjOw8JsgJYuINnavKovPbWlkhvumGjwx0xeSAAO4lAgyUmHnyq10PDsAlRsBy60
      |su8O6VY8QSYVy8VO3pJ5wJiPZIOLloRciWZIH1z/IrWswe0NizOZXBUldptYgdAB
      |rGjeu8HxcmIi
      |-----END CERTIFICATE-----
    """.stripMargin.trim

  val enterpriseCAPrivateKey = {
    val hex =
      "308204BF020100300D06092A864886F70D0101010500048204A9308204A50201000282010100DB918583D9FBC8FF65695E0F6EAB1590EE17F90789B42A495DEBE40A81463C14606C5FD84905D91DBD793D12EB482CEB687F56D7B8C4D1953C0137F58EACA51F4CE4A2E48EC0FA55D482092B4DAD6253E4A3026C76519DC64A379F205A5BEDED403B2AC88A24FD018D05D1089270F1742D267A3B3C16598AB09A493987BC93A45B5EB21DFDBD29D7673188C51CE4024A9B0CA9CE43B850FB0F9DBE980A5DD5387C8DA817443784D5AEA9EA4C277780D32F4D8CADFE86119855007186ED878F811A6C5F6C707920D4BE3369667881FE3696E32F6CE2C5CB9FE61743F7C24822F186414A95BDB8E7C3CACBE94E641CEBD94F62E4841FE7319C5A8B98AE5FFA0A3702030100010282010045236F0BE42D8D0EA2C3C98B097994DA64A6A6D371508A8A3CA9654ECB832EB2E9E3E650483A2FB25631E181DE15859380FDABFE549FA131214A6EF10342A8E210C7E3E51D7075C3661DA63E7D00AE38258410E4CF6306CFE419DCA106E2F0AA26F21A98382BCA815D032A5DCD23045CE544BAF38109B69B5DDDCF55EEC07A2A8EB6632BCE932ADFBB749260BD3CE9A5DEC15AC53EEE5873FB59192F6F47AA913854E5B09411FEDAFC749FFBE2DE193CC3BA7FB7E3BE1D914AE2F2D2A4FDAE422944CD74CC3582DAB8F528612A4BE404D88149072167FA5A97F88530723FCD1DEA7FFA29A5A1E0720F2F807648B43AA77060E66E3DDBDFB6006A738CEF9DCB0902818100FDA0383077185C2C56A84DE5294C97AC2079E3E89E2F1C71B09F520C7B3A615DAE8B88C11C04240F0897BED3360CC619A12AF4B93E534E7D6C2DF4C79C370929A08AF157BBC20AB5F986F112BA38FEC23AF891A652260D4C2626F3FAAAECA4BABE9EF03CF9C9F5F67729BC83646A61A08D575A8A2732697C369FD89099E845AF02818100DD9FB021456E0F52F2437A42F4BE46F686A40C05BE1A73F7704F7DD999C7E905F51D3F01E1098E07C74413A2BCEE4117EF3709BB5571FB3D63EA8379DB6491887D1CD2C5CE8864765D1DD646205C28F59BCBA2479F909194A7ED522102E2BFA613EF089EA57C08BF0BF302FBDF8E2D035C0079D44E4370D351CBC2026E39ADF902818100F84D0055AA7305E23EA09D4A2A299B1FDFD79561EA63930456F7535B76D50BF7AC675CE639E86FE8EBEFABD999C3DDB9BFC88F3840254CE58BA05E5181C57BC9EE2BB8E5BCA2D6DB9B441A05CC9CFA04EBB8E8D71CFBB5EF0437048B370560AC96EC81A420A431922ECD848A5A27B0167FE9B27128B8B8FEEB77888CE0B0BE6F02818100BF50607CF830802DFC505FB4790DE0B863962D82AF8EAA5909ACB55928B537E51AA93A80E6C096C9042D323E239610BF16938E6516E7A41864AE46FCE47536647A8C6D2EB0917117F45E1360CA0284A130F2628E2DA260E9D0E4BF271C149D984250F041F35CD538069AAB12BEF33ECC4D996391F055AB89E06C627832AABC1102818100DB70A22A8179D90D8A8B295D790AC30DA85C0C1C2AF5A799AD277F2C2F029D76865618F0E2D75BF0F52B85AE66477FC3BED1106ECC34C3FEC5F15083EB26E23DA9E020B44C66D28003276A5EE23406300A83717E906A362665AAFC552180513EAB0828CA323372971A614C79DA8C75180D44EC4009E8D87D9CB7B275CF84E534"
    val bytes = fromHex(hex)
    decodePrivateKey(bytes)
  }

  val externalCA =
    """
      |-----BEGIN CERTIFICATE-----
      |MIICwzCCAaugAwIBAgIEXAtS/jANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhl
      |eHRlcm5hbDAgFw0wMDEyMDgwNTEzMzRaGA8yMDYwMTIwODA1MTMzNFowEzERMA8G
      |A1UEAwwIZXh0ZXJuYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDT
      |c7m7Y4jSr4cBAoic3bfsN9OtaZLufNLYzzQVPNtsU0zP6f/JEmCfeN9ACvZgkgaI
      |z+IsquWixkHGWFFQHOXWrnT25nWpqqlCscjWS/bcgiYrnclMP4IyfXXq5stTUD+V
      |lS2P3b8sU4pM7ELLVDP23NM89bLf5TmURZ+OK5Cbu8neasszJRihJUv1qNs2Z5yS
      |YuHfj7omgf02ImvCNXOSNb/xRbJNq0AlfZr84o8aeVbshD4yr4avYKL2EBjlKsom
      |nf/+oLriIuqWkUJ4MAPEa7v7mv5mxn81l7+8Ja6tD/P8Lq4kPQUZuByrLTDPc6AC
      |7jy2rFBs3J0keCu1shQ5AgMBAAGjHTAbMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQD
      |AgKEMA0GCSqGSIb3DQEBCwUAA4IBAQCOW3pGQjpePluOTD4GIT8caRR3Vy09GU6I
      |jBrG+WzKecngMYMMgxcYvtdMV89oJGuE0gLSPy41AUE8tCxiC8GTxLIYs0Svz92t
      |nZt6OsZZ0f+s26YtX68eXuno6xSjQv0HuWIkvCwa8v+73TczktPw7AQqR3XNWXOP
      |65V9Mk14Zl5DisohGG+ABhrAf9QUd5QAVoslguIiOJLe3YH7NnCrpUr9X2DPNgpL
      |U1mw00gnpmowNWrGFzp4IqEnefjVmIrhp7UsRTD+5rzoJMOsiMGqergJRy0JEj/V
      |q2m2Pl9gK4rNJdow9Xnzw9hCBT5T2r2kpVWeq+Keg8Pb5M4c0aV7
      |-----END CERTIFICATE-----
    """.stripMargin.trim
  val externalCAPrivateKey = {
    val hex =
      "308204BD020100300D06092A864886F70D0101010500048204A7308204A30201000282010100D373B9BB6388D2AF870102889CDDB7EC37D3AD6992EE7CD2D8CF34153CDB6C534CCFE9FFC912609F78DF400AF660920688CFE22CAAE5A2C641C65851501CE5D6AE74F6E675A9AAA942B1C8D64BF6DC82262B9DC94C3F82327D75EAE6CB53503F95952D8FDDBF2C538A4CEC42CB5433F6DCD33CF5B2DFE53994459F8E2B909BBBC9DE6ACB332518A1254BF5A8DB36679C9262E1DF8FBA2681FD36226BC235739235BFF145B24DAB40257D9AFCE28F1A7956EC843E32AF86AF60A2F61018E52ACA269DFFFEA0BAE222EA969142783003C46BBBFB9AFE66C67F3597BFBC25AEAD0FF3FC2EAE243D0519B81CAB2D30CF73A002EE3CB6AC506CDC9D24782BB5B214390203010001028201000A9AB1CF2AA80B48DA3B1166CB2C78B37EA93DA2747299629EEA3A9BC60D8B05326E4AE1EA5CE2E8F1D035BA01AE7379A3157F2B964BD08F4E1A7B060E3FCF6C50C61F8BB7383C62CE01747D001A453CBC5AA6486E167BEFB99DAC461EC99D80A82919BBD94C63C0B21D8C21081414F710640243F57B3257B78E8BA33EF41045E7525C6A2F53081609B057174ED20C39C1FCB68B69BA02FF9EB19F8CC53F34ED0532B09B9902B230E48DE5A6CE2B83B1828DB652CF79FC1455056EFAF0B63FF737ED4870833B81D255D47B1C17490867827695622A3BC5F4CD13AF3C4942D7321EB04B8D1E1EE4E9FC8A1639BF33887E4A423B39D45A0C2D290317CDCA9EEDC102818100E92FCEBF062C2E429E70A0220F953FEA030022D6A38A8731D3548B272536D80605926E9E38092A299B9A5833E5E67EF6336FBB24268554D10D9969CFAF9E69C8BF5933E4680A175755AEA7FE2963A879ECFDC587C0D463772B80D853FF68683E5D005B1C1840B6F9A2C81DF8F9D3FDDF41C4A8B9561385460AF8BABE89A9DBED02818100E82391D3CDA4BC61EB68EE1D8BDC87AC77D37D7E41A6951CBA595E10D4F93EE467090554FED0752D46C9DA40D92AE7245A4770AE6B211719F464861858FB82C954A3CB8C1228C3E6B6F556C9C8031C9FF384FFE8B0B2E0DB8FB6310AA46BD40FF68C873B4D69A27D704CF66BC4F46BF3D812D28143A85A3366D812EEE78947FD02818044CE7088F93F4C1F28353F6B0D8212ABF05AB7ECF1B0CC97AD2E032977D7A9028DDE5979A23B420FA8F47016503E25346C9509796F4C646C9340B3722EF5E56CF0D957708C2A7E1CAD11AE4C56D62B3E5EE9BAC185EAA5B6E245508FE88B5C471A96224C35F3D289F2B86DEFAB781C2F266EEB02551DC9739385354547C5B13902818055B9DCFE84B0D348ADF0C00E7539E9788D7FB2964F943EF8AEF095C64D8005F3BF011BD0F990EDD4DC916A620C50C5AF2D0FB8D31088D5C925F1817BB8509949D451F0B737758A72C719EF04F13204FE24A5F7036D4D81B053700AC84D53ECAA407840F06B7419278DB33E452A24C140F98869E8869DC341BC370B36E29655D902818100CED71C14CCB3102F64021CB43425A482ACD6B782531E6AA22F19218CD32EEF1F95CEE1D18CD9DA54956AB1219A5D367A689493C51FF651F4D845BE54EDC9B6CF20F0019274D5D54BDE9383CF6F88276E0ED68D604D8FC9FD8D2FD3F6A370D3CA1C1D1775B06626D9A26BBC94DCF0766359232F6AEFB15375D030C5DE9B1818C6"
    val bytes = fromHex(hex)
    decodePrivateKey(bytes)
  }

  val validCert =
    """
      |-----BEGIN CERTIFICATE-----
      |MIICqjCCAZKgAwIBAgIEXAtTSTANBgkqhkiG9w0BAQsFADAcMQswCQYDVQQGEwJI
      |SzENMAsGA1UEAwwESU9ISzAgFw0xODEyMDgwNTE0NDlaGA8yMDUwMTIwODA1MTQ0
      |OVowEDEOMAwGA1UEAwwFdmFsaWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
      |AoIBAQDk11L4C2IdRaRrRzIUytNeNFZw0MRZ9C2xGc1ksDFz5/XJm5As8F94HNsm
      |I3xdu1q1iGC9wan0twqw2FCdcRmnpmepuor2ufZ6xp+Q/Gi4Ahf/S8R5M3uCnXSW
      |s3N6jM4zNHdDxFSRzrHZVVyFE/oI71xoVg1ui1G4L7bIImBhBc0lWETThQKK52ss
      |FFEYo8eG73tL/KvW3fq1jf+8wr1r7nQA2xfr/3XeQNntlAT3q7IH5YcIgjHg4ZZu
      |tVfP9rppqL/xd/3q+/P/dVht8OfVnYej1IxO1Sr2rzWhLsmierWx7pCfbZeB6smw
      |ok7vWnZOnOMju2Zm84j8FaVVtIV3AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAMnv
      |XDi64qkk9HmfAsBBM2/2NWLEwe8vnOHMFsiJJQhFWcC39MNjC1+EPbV81m3Jz2Je
      |V7MyzKWs1WQF2tpbuE3xe8wVIIiL6O/Gr5U9pW20fYs8PHoNMWYatj7oigkYWD4n
      |cnVtFxUuTro86gdj/uXFI/1lBw/W3EEexa1cNAO1Up2b9FsPpci1iSGN7gXkbmRA
      |isCMj3CGkFxzjqaXYJoFhXfSi683UX+I14MBKE/bwj0oeEMtmyHQ8LaWm9GTbcJ0
      |01tF+Yits/jjeXAEOT3vhxzgOyWWJs8CGqu7H3Uf5eqohuDkqtJRjoOgzH7Zem9Q
      |gezppWASH86vRZmiF5o=
      |-----END CERTIFICATE-----
    """.stripMargin.trim
  val validCertPrivateKey = {
    val hex =
      "308204BE020100300D06092A864886F70D0101010500048204A8308204A40201000282010100E4D752F80B621D45A46B473214CAD35E345670D0C459F42DB119CD64B03173E7F5C99B902CF05F781CDB26237C5DBB5AB58860BDC1A9F4B70AB0D8509D7119A7A667A9BA8AF6B9F67AC69F90FC68B80217FF4BC479337B829D7496B3737A8CCE33347743C45491CEB1D9555C8513FA08EF5C68560D6E8B51B82FB6C822606105CD255844D385028AE76B2C145118A3C786EF7B4BFCABD6DDFAB58DFFBCC2BD6BEE7400DB17EBFF75DE40D9ED9404F7ABB207E587088231E0E1966EB557CFF6BA69A8BFF177FDEAFBF3FF75586DF0E7D59D87A3D48C4ED52AF6AF35A12EC9A27AB5B1EE909F6D9781EAC9B0A24EEF5A764E9CE323BB6666F388FC15A555B485770203010001028201000318782D1ECE911933F0D9B2E6CCD5FD44E8C6F84E20BAFBEE729281A4721E46DDF06F0848EACE6EBD1ECA549E2854D67B05E785E99B8CAFC530DA290D02D70EAB84A911A5997449349C80D347439E944578B2C1D1C491B78C9B0E35C22A8BF5DD94CAA47DC4DF18DCD30834B5A8ACFCCCE34FC9BD69D7674A648CF9A05C5A77E1126194CCB2E6086552192E7B210D1FD2E4B5D3534EC120835402AB2EFCCF4414A728FB1227006F08761A90E6880C0718F3DC8F878D10A7BABFA3252C944B932F22238950521C070F94DB66DCD7BA7D02A3183A21A61F2B5D886ED67ADAAAF7A4EA5827B6DA77A6912D45857BD2FCCA5CA3CF502571475C6FAFA581B6AF2E5102818100F7BA2C83B2DE8F998ACC0C2A68BDF04B6F39619BADBD512E55D599BE56B0B1291C042D72F14D1A5C54744F4729637691EF3DD5A0FDD57CA427F19C933408031DB67A6BD71B8689BD425FB4E614CCEBCB473EC4C7D0F9042FA2D3819D1CC14D327E007C8DDE0EE8F9F6486597EEF22F36F8AB5BB639E6C2415C797CD20C47A16D02818100EC7BB1353EEC45DE424C2969112F9F04BB30D469CABB30627854B174C85E3F49E42CAB24DE5EB261EEE2937C2BC0C2AF852DBAFC25EA9921DE712E88F157B6502F32F2A88D4CA854057776D5B099B97315884DD9DE2EF6665A58A695A897304E9AAF67542A59D6C665BF63456EFBF3AF31D147245D654E927E08960BA31B97F302818100840F7A9586B040CB3083D064774BF222B49B595E7D833418C867433B85C951D8417834A656DEAC93D5EDDF296775FF8A92885B2F24C23F5CDF725CEED849012840D4085336F844CB60EBD66AE561CCBDA4306104C871477B0189514A693EDF2170AC5FB9DD4C0384E576F8B9C306D686AE8FE32744BCB087D97D663E2F8FAC0D028180228B0ADE913B6815482FE1D8A41705AE663D82B995507487DDB5D95A0AAEA1A6047B75E063CF075580D47DE0A46F7AC0B2BE7452C2A31B0D3475E9EB3CFDA7F6DC7E1FADF93DDA54B39BB8B30C21D851F4323DD4F63C7BE78588EF846AE4F2BC78A1E88105D2ABA9BD51108A22E510BA65978141D196ABBC804676CC6A5DEC7B02818100E4F930AD8849F3ECBFD8F275C111CF887AE7E1E270A50E16328A688C9BC0338570D51FB3700D8AB989305D882907B188652D5A30BF93F471A9F0CBC0722B05D1FEDB25AC2B5732E5A6392279B82A14746B6CF19A95A16FCDC57607A1673749C4467304D7BD2B228DE90094881144B95386CE35E0EA2BB24E58BC51E1A8229D56"
    val bytes = fromHex(hex)
    decodePrivateKey(bytes)
  }

  val expiredCert =
    """
      |-----BEGIN CERTIFICATE-----
      |MIICqjCCAZKgAwIBAgIEXAtTeDANBgkqhkiG9w0BAQsFADAcMQswCQYDVQQGEwJI
      |SzENMAsGA1UEAwwESU9ISzAeFw0xMDEyMDgwNTE1MzZaFw0xNzEyMDgwNTE1MzZa
      |MBIxEDAOBgNVBAMMB2V4cGlyZWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
      |AoIBAQCx4YFUyoqC9oxhpA+X34Ckb4nIAJhv+o5VhyUlRs+ordysLV2pOcjTDrq3
      |Lhz1FXkYuGfAcMo90Og4CcehOzar5sOxjByJDEHBT2jI5/F9ilCFf30Vw835Qpy+
      |/kMKqoh9YMhfRonc3MJLOTR45JprFilnsHHMW8rvvKxZNbaeevPvWSIxq47ws86H
      |lW5U9Dm1QVNLVku6ZiIGv5WkCwJp9iNMWdbM3oitZAg2b7p0dX3VQntu06a/qz0m
      |9dp3zxsA4u6hYmUSz4e+BOsVI+2cqlFCEiVEk4ina0NIpqcAfxs381uQTtjoMju8
      |qFCd8N60U+8CmHp3ElIzyshT+e1xAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAHXq
      |uWlRTSW9shCBtF9KnvwbLKMOWy6CWEQGk7VI4fIzIrt4aer+i2KhVlUPVkrIAH4N
      |Kfx1nIj0OhJ0+rNgC5jXHuQY65DLx7uwpIj//bvuIPfSzXwUNIjEEnZmj1/KrsId
      |eNZxZZ1QkRJp3m9BqcllxVDLK0ILGwAOJbrV9O3hsGnPBXMJfYJp7Y+wSICxE6UR
      |9/vwJ5SKnQ+M62Yirle/NK/0+1e7C923cVq82UXc/0YNgpSENx9Eotquaj5XG2R5
      |C8rneHhK9JhZsB1h/qLZGF1e7E3IPiwhTksBKUcmocACANoxZrCUsWmPt9bbInLG
      |ImJVIB87QSwNcsjsA/0=
      |-----END CERTIFICATE-----
    """.stripMargin.trim
  val expiredCertPrivateKey = {
    val hex =
      "308204BD020100300D06092A864886F70D0101010500048204A7308204A30201000282010100B1E18154CA8A82F68C61A40F97DF80A46F89C800986FFA8E5587252546CFA8ADDCAC2D5DA939C8D30EBAB72E1CF5157918B867C070CA3DD0E83809C7A13B36ABE6C3B18C1C890C41C14F68C8E7F17D8A50857F7D15C3CDF9429CBEFE430AAA887D60C85F4689DCDCC24B393478E49A6B162967B071CC5BCAEFBCAC5935B69E7AF3EF592231AB8EF0B3CE87956E54F439B541534B564BBA662206BF95A40B0269F6234C59D6CCDE88AD6408366FBA74757DD5427B6ED3A6BFAB3D26F5DA77CF1B00E2EEA1626512CF87BE04EB1523ED9CAA51421225449388A76B4348A6A7007F1B37F35B904ED8E8323BBCA8509DF0DEB453EF02987A77125233CAC853F9ED71020301000102820100035BA4A4925202F2C6EFC73046EB80870226C78678DA38D077ED7E2255F3D0BD2EFEB658C7BB7C36BD4701B322776F3746F3E0BC07990EC98F3FB312106170F8D5E974F4265C0135EAD17E22B84BB5152FCBD45E3AF3644397CA041A424F5CCCA8B2C377967A1EE7F13848B13C94C2B441B1E887E27F134EC97FAE207D40C83D3577266B6ADF88AF24E9AEF4DE4AE9737ACC30EC617A4CF2B463700E21FD3977B4A3F4656C6D7D06CF7DEB011874E9DE25029C61B26AB1C82E46416ADA43939C7686F01B11E66E89E53641762962BB9E0687225E4C1FD7A106D925C97AE1DBDB62D58F5BC31D3C3FFBD02DD2EB88B8BE94D736CD4E600CE945E9C311442F676102818100F2714E55EE4901BE7971738048B06D7A3FE8756C4D748B7B960743F705F2F9C509495534333BC9F3E44D70D63B4CA611C517386DC3470E2DBC6B15CF5E513743B039413EB09924D2ED414054CAACA49CE7F7FE47645425996513FD0DDAFF3B8092885B59342CBBA3558989FE2FDDC7C9C9BBE217FB154CCBEC99E422167971A102818100BBD3F6CA49E31D7C9892FB86A16358F9E350EE9DF08753BF3E62D7AC01AA52A8A73DB8376E891C4764ABDF64F8D8C4D8A1A177BF92C45BDD54BAB90B573E31ECA00CE83D6F421B6A70875CD204E91DEE91506D6FA1E293F5229EBCCEC95C5FFAA74507476998B8986EA1D941148D408477CB8EA386D4E8683D2AAF5B58E589D10281805A95D966241565306D21E5BD0DEBD5CBF2AB018CC8D7FDF1DC59B49C4CBDBF734E87F6ECFD239ECEA1040A6011620F3EDE7C519A39778825B09BF65737EF728DB8FF7B9057DDB0B39AF061800D063AAF61C0F862666B466D2D262DCC0A828911FE2E32AB7EE223EDE05CF691620324CE11B140C6230B8F59367B3D913B027F610281800DD4CC05956F4E0A90C9B20FF5EE74ECE1DA61D7EB906B9057ADBBA804EF5FEADF75E20CE2ECE1D2380D9803BD7768F772DF8B0BE668E342E72C60D7FEF2AB867B3AB8175E0C062CCE60896B45C54CD8F6866FA89AC92E900C9E97D4BA6B3CFE1E372D140B289DDF4BB64B63497A25581BE2377CBF3F0A6632AAE402DC06FB210281810096F8DF808F6796DAB2893DCDCF9FA55E19DA082A017AA1C69C4283AC0D4EC480459D9A6EE3CBF94CFB1659600D7C9356965917C3202DD17CA86F358881B777434BAE0E72F3D76AC11F220C2C80C5F072C0C4D60FA1A12D74E3C5E8B532F7C402F6592A573DBAB6FAB498487B0AC74C89A41636DF9C636A590B62835E4CAEE2B4"
    val bytes = fromHex(hex)
    decodePrivateKey(bytes)
  }

  val notValidYetCert =
    """
      |-----BEGIN CERTIFICATE-----
      |MIICsDCCAZigAwIBAgIEXAtTsTANBgkqhkiG9w0BAQsFADAcMQswCQYDVQQGEwJI
      |SzENMAsGA1UEAwwESU9ISzAgFw00MDEyMDgwNTE2MzNaGA8yMDUwMTIwODA1MTYz
      |M1owFjEUMBIGA1UEAwwLbm90VmFsaWRZZXQwggEiMA0GCSqGSIb3DQEBAQUAA4IB
      |DwAwggEKAoIBAQCFEDZdVpNtzj9L8O4DWDPvDfAJptFKrgjkF14udrqwXiT+KFf8
      |GbdsnodBYBn8Ag0v5FomwHaNfHgLW1jxiBtQRCoDfkBDzpN4Xz//zY/z209QH1yr
      |bDNTgzOKFoSiOKAEXF6J0lDhkNFWKrAgwJoLsBzZtKmg7hD4ooJ0HyLRCBss18gc
      |qM/Nyt1zUc4PUJ8hfR2OqWS0eJEgGujIDAaJpBY6tZL45iWEiLNS1PFC310E2C5p
      |6IBaI6QC3SgOSJByATZXop2crp8HOymLj4dvYDheYJ9xo/qIXU3j1qLsFUYSwgUp
      |76eeAjfs45GaN8bv+uGDV4lfq+LSjwIlzkzJAgMBAAEwDQYJKoZIhvcNAQELBQAD
      |ggEBAEqZmHWGSceul8HxExhEIKJV1OJNXXjsYtNoJrSyFsWy7atoA1J3VfdfiFPP
      |mYQn4zoC0IzuoNr8+dTSxKICbadwpNEx/wcy3wRdsLna1LwNj3T5RHtbYv3klT+8
      |BMCnEaywF6sRrs+uR8WVwvKs/RrWo7VTyDFzaZNGsMJaOy+Adr0XIDuWTbVNfuNd
      |pPOw7nRP9z7DpIjxCgTCX/TzxO87H6U1+6hgPXTaAJ7/PLbR9qFmi69e9hzQOlwZ
      |OWSro9FNdLRmydkJ6/+o0aMkMlAmSbQuBrNTnOON3ociYR+v5xjJSxPtKytq5YOk
      |onixQmQmBYHJd+0l9gUCUB2hE3k=
      |-----END CERTIFICATE-----
    """.stripMargin.trim
  val notValidYetCertPrivateKey = {
    val hex =
      "308204BD020100300D06092A864886F70D0101010500048204A7308204A302010002820101008510365D56936DCE3F4BF0EE035833EF0DF009A6D14AAE08E4175E2E76BAB05E24FE2857FC19B76C9E87416019FC020D2FE45A26C0768D7C780B5B58F1881B50442A037E4043CE93785F3FFFCD8FF3DB4F501F5CAB6C335383338A1684A238A0045C5E89D250E190D1562AB020C09A0BB01CD9B4A9A0EE10F8A282741F22D1081B2CD7C81CA8CFCDCADD7351CE0F509F217D1D8EA964B47891201AE8C80C0689A4163AB592F8E6258488B352D4F142DF5D04D82E69E8805A23A402DD280E489072013657A29D9CAE9F073B298B8F876F60385E609F71A3FA885D4DE3D6A2EC154612C20529EFA79E0237ECE3919A37C6EFFAE18357895FABE2D28F0225CE4CC902030100010282010001B0D024D20F7CE2FB14B4D5DFC2013E1F3CE9D747DF4A2432FA856E5380DE589BE184D3822A351585ECED6C9F117FBF2C8C1B1F21ED7FB15178C111ACBD904747B4D6F3EC35505985EE83E4284495125195C3EEA598F20CCE180ED99AFED1112B6D03D3B1784F03CBF051D6BBA89A061164E13FA8B2E5DD118A130FA80D387F49146C5F525D24C21824D2B0914D96B26CD160713E12192672FD01B8166543BCDBC367ACB51FE0C46728DEB8D18F864010C2C572E3A4E0C20BB4FCF26A9F62C72B005E6CB56A35BD18361915D60C82C94BBC21A69AB6454539369CDE4545B99A9992DDDC54B18E7D34926F44DAD44884693711D30C3C76F344280AD00D7FF45902818100B901D2F38C58643CA02FCAAB2A4F5F1DF1D0BBE4C192700FD3435DE71349D189D44F9C494873EB3650EB3DCE81C8866F1D775F8BFE08380D1EBBDEC87DF339AEC225CD3D456B4C80E4585E1302677706AB9D612B229D388E0DB091E57B95546C6BF54FAA81F201D7E54792F33ABE70402E4613472EB11EFF53EEB635F6DCF65D02818100B81FB074E8F53A850D9EDC6518D57E94EB3CF2F3708E2A0C295AC8A901C91553964429BF837DC9EF7076E99B7ADDC7C92F766926E591846D76D4D149954AADEE63E8DE3DFBC3DDD7B98460990006D1D81CE8C632B38F8776A9064BA1B6A390DB8E0136B6784FCC956D7185B87AA9AF260F10024F142E6E320B36ADD1E5D5315D02818100B4AC8558F79C72F789F0625A5A4D7D347F2D3BF1A0E0E3B370BBFF7E6525D80E645B02E3C66FFE2AE34778EAAD702969663B68020D29F5A34A7A6A8D1E036437B8BEB5FABA4A9941DEBE35D116ADF85D79478ED7534C7B28AF51DA8963F167AB229B451BDD1F7C915D06530A5A3A14E178CF52905796FE1097E52DE8F196C4B9028180468534A3827A3260B597CBD818CBE4808B1CBBFCCB7657DA729867D47B6F95F07ED43A9D3472A03E49F7F17F706EB34F76134730F3AA696B37A1494B8297A8C86E91C9553A3189AD4F4BC967B05FEC4D76BD1CF45C5BB3C999F164545ACC88F5DE8CCE74D2DDD580C1FB41F9275A08506E62764FED6DDF1CE1B89E988F0BB9AD0281800FEA388A38A4EDC2C9F55D9D200DC813B7A8D93B342AA6F2EAEEC40A4E9B431E8440F523FFD966A01F08DF4E585B881C5866EFB7C5C9E3A9981A32105BCF40A0E80CA15D24C1CD90C0AF71F9ED7B245858A9DF917CCEAD08D219EF3EE455EFFE7422069C29E43D895B5125764E9EED86257DCE7F1E0186FC4213288FC0824A13"
    val bytes = fromHex(hex)
    decodePrivateKey(bytes)
  }

  val singleCertWithCommonNamePEM = validCert

  val singleCertWithoutCommonNamePEM =
    """
      |-----BEGIN CERTIFICATE-----
      |MIICKjCCAZOgAwIBAgIJAIDRcRzEjXqrMA0GCSqGSIb3DQEBCwUAMC4xCzAJBgNV
      |BAYTAk1YMRAwDgYDVQQIDAdTaW5hbG9hMQ0wCwYDVQQKDARJT0hLMB4XDTE4MTEy
      |OTIzMzgxNFoXDTE5MTEyOTIzMzgxNFowLjELMAkGA1UEBhMCTVgxEDAOBgNVBAgM
      |B1NpbmFsb2ExDTALBgNVBAoMBElPSEswgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJ
      |AoGBAMao8aiKMzhExgLI7X5gYfKVEQ3ek/rgne3l8i5S4rblaoUDvd1vnX/rRWwH
      |g3pxFMAKRZjkGNXC9yLr0QUlFhjgIPlNeqdPVpU9/pUKDWTMV2wTxPKMJGh0OnKq
      |nho4YjtZFoccVwM8+ED5XdT0UHVnqsZ7sfzRfxcK6HGurVwRAgMBAAGjUDBOMB0G
      |A1UdDgQWBBSedUQMK6Sdf9he6SGTDcyeYQ45DTAfBgNVHSMEGDAWgBSedUQMK6Sd
      |f9he6SGTDcyeYQ45DTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBAKcL
      |wKss+0LnLHPeqMCOZCn87L6V+tibtIgPvh67paXw4UNjJJ/CO3AORKmLs+MOvyYU
      |7gKuvyvvhH9KJOK9myTOdeiS5O68EXchxxVR82hN+FAhsTHkuklDf52EGqSIA1s6
      |t00zWJV2DMbGusegUHFpZNiaNnFJsPjT4jU4tjTZ
      |-----END CERTIFICATE-----
    """.stripMargin.trim

  val twoChainedCertsPEM =
    s"""
       |$validCert
       |$enterpriseCA
    """.stripMargin.trim

  val twoUnchainedCertsPEM =
    s"""
       |$validCert
       |$externalCA
    """.stripMargin.trim

  val twoChainedCertsNotValidYetPEM =
    s"""
       |$notValidYetCert
       |$enterpriseCA
    """.stripMargin

  val twoChainedCertsExpiredPEM =
    s"""
       |$expiredCert
       |$enterpriseCA
    """.stripMargin
}
