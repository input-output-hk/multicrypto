package io.iohk.multicrypto

import akka.util.ByteString
import io.iohk.decco._
import io.iohk.decco.auto._
import java.nio.ByteBuffer

package object encoding {

  implicit val ByteStringCodec: Codec[ByteString] =
    Codec[Array[Byte]].map(ByteString.apply, _.toArray)

  implicit class ByteBufferConversionOps(val byteBuffer: ByteBuffer) {
    def toArray: Array[Byte] = {
      if (byteBuffer.hasArray)
        byteBuffer.array
      else {
        (byteBuffer: java.nio.Buffer).position(0)
        val arr = new Array[Byte](byteBuffer.remaining())
        byteBuffer.get(arr)
        arr
      }
    }
    def toByteString: ByteString = ByteString(toArray)
  }

  implicit class ArrayConversionOps(val array: Array[Byte]) {
    def toByteBuffer: ByteBuffer = ByteBuffer.wrap(array)
    def toByteString: ByteString = ByteString(array)
  }

  object implicits {

    implicit val ByteStringInstantiator: BufferInstantiator[ByteString] =
      BufferInstantiator.global.HeapByteBuffer.map(_.toByteString, _.toByteBuffer)

  }
}
