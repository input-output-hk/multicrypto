// build.sc

import mill._
import scalalib._
import os._
import mill.api.Loose.Agg
import mill.scalalib.publish._
import coursier.maven.MavenRepository
import mill.scalalib.scalafmt.ScalafmtModule
trait CompositeModule extends ScalaModule with ScalafmtModule { outer =>

  override def sources = {
    T.sources { millSourcePath }
  }

  override def repositories =
    super.repositories ++ Seq(
      MavenRepository("https://oss.sonatype.org/content/repositories/releases"),
      MavenRepository("https://oss.sonatype.org/content/repositories/snapshots")
    )

  override def allSourceFiles = T {
    val submodules =
      millModuleDirectChildren.map(_.millSourcePath)
    def isHiddenFile(path: os.Path) = path.last.startsWith(".")
    def isFromSubmodule(path: os.Path) = {
      submodules.exists { path.startsWith }
    }
    for {
      root <- allSources()
      if os.exists(root.path)
      path <- if (os.isDir(root.path)) os.walk(root.path) else Seq(root.path)
      if os
        .isFile(path) && ((path.ext == "scala" || path.ext == "java") && !isHiddenFile(path) && !isFromSubmodule(path))
    } yield PathRef(path)
  }

  trait Tests extends super.Tests with CompositeModule {
    def ivyDepsExtra: Agg[Dep] = Agg()
    override final def ivyDeps = ivyDepsExtra ++ testingLibrary
    def moduleDepsExtra: Seq[PublishModule] = Seq()
    override final def moduleDeps = Seq(outer) ++ moduleDepsExtra
    def testFrameworks = Seq("org.scalatest.tools.Framework")
    def testingLibrary = Agg(ivy"org.scalatest::scalatest:3.0.5")
    def testOne(args: String*) = T.command {
      super.runMain("org.scalatest.run", args: _*)
    }

  }

}

object deps {
  val shapeless =
    Agg(ivy"com.chuusai::shapeless:2.3.3")
  val akkaActor =
    Agg(ivy"com.typesafe.akka::akka-actor:2.5.19")
  val akkaTestkit =
    Agg(ivy"com.typesafe.akka::akka-testkit:2.5.19")
  val akkaSl4j =
    Agg(ivy"com.typesafe.akka::akka-slf4j:2.5.19")
  val scalacheck =
    Agg(ivy"org.scalacheck::scalacheck:1.14.0")
  val scalactic =
    Agg(ivy"org.scalactic::scalactic:3.0.8")
  val scalatest =
    Agg(ivy"org.scalatest::scalatest:3.0.8")
  val enumeratum =
    Agg(ivy"com.beachape::enumeratum:1.5.13")
  val enumeratumMacros =
    Agg(ivy"com.beachape::enumeratum-macros:1.5.9")
  val pureconfig =
    Agg(ivy"com.github.pureconfig::pureconfig:0.10.1")
  val decco =
    Agg(ivy"io.iohk::decco:1.0-SNAPSHOT")
  val deccoAuto =
    Agg(ivy"io.iohk::decco-auto:1.0-SNAPSHOT")
  val deccoTestUtils =
    Agg(ivy"io.iohk::decco-test-utils:1.0-SNAPSHOT")
}

trait IOHKModule extends CompositeModule with PublishModule {

  def scalaVersion = "2.12.7"

  def publishVersion = "1.0-SNAPSHOT"

  def pomSettings = PomSettings(
    description = "crypto library",
    organization = "io.iohk",
    url = "https://github.com/input-output-hk/multicrypto",
    licenses = Seq(License.`Apache-2.0`),
    versionControl = VersionControl.github("input-output-hk", "multicrypto"),
    developers = Seq()
  )

  trait IOHKTest extends Tests {
    override def testingLibrary =
      deps.scalatest ++ deps.deccoTestUtils
  }
}

object src extends Module {
  object io extends Module {
    object iohk extends Module {

      object multicrypto extends IOHKModule {
        override def artifactName = "multicrypto"
        override def ivyDeps =
          deps.shapeless ++
            deps.akkaActor ++
            deps.enumeratum ++
            deps.enumeratumMacros ++
            deps.pureconfig ++
            deps.decco ++
            deps.deccoAuto

        object test extends IOHKTest {
          override def moduleDepsExtra = Seq(utils)
          override def ivyDepsExtra =
            deps.scalacheck ++
              deps.scalactic ++
              deps.deccoTestUtils
          object utils extends IOHKModule {

            override def artifactName = "multicrypto-test-utils"

            override def ivyDeps =
              deps.scalacheck ++
                deps.scalatest ++
                deps.scalactic

            override def moduleDeps = Seq(multicrypto)
          }

        }
      }
    }
  }
}
