#!/usr/bin/env node
/* eslint-disable max-len, flowtype/require-valid-file-annotation, flowtype/require-return-type */
/* global packageInformationStores, $$BLACKLIST, $$SETUP_STATIC_TABLES */

// Used for the resolveUnqualified part of the resolution (ie resolving folder/index.js & file extensions)
// Deconstructed so that they aren't affected by any fs monkeypatching occuring later during the execution
const {statSync, lstatSync, readlinkSync, readFileSync, existsSync, realpathSync} = require('fs');

const Module = require('module');
const path = require('path');
const StringDecoder = require('string_decoder');

const $$BLACKLIST = null;
const ignorePattern = $$BLACKLIST ? new RegExp($$BLACKLIST) : null;

const builtinModules = new Set(Module.builtinModules || Object.keys(process.binding('natives')));

const topLevelLocator = {name: null, reference: null};
const blacklistedLocator = {name: NaN, reference: NaN};

// Used for compatibility purposes - cf setupCompatibilityLayer
const patchedModules = new Map();
const fallbackLocators = [topLevelLocator];

// Matches backslashes of Windows paths
const backwardSlashRegExp = /\\/g;

// Matches if the path must point to a directory (ie ends with /)
const isDirRegExp = /\/$/;

// Matches if the path starts with a valid path qualifier (./, ../, /)
// eslint-disable-next-line no-unused-vars
const isStrictRegExp = /^\.{0,2}/;

// Splits a require request into its components, or return null if the request is a file path
const pathRegExp = /^(?![A-Za-z]:)(?!\.{0,2}(?:\/|$))((?:@[^\/]+\/)?[^\/]+)\/?(.*|)$/;

// Keep a reference around ("module" is a common name in this context, so better rename it to something more significant)
const pnpModule = module;

/**
 * Used to disable the resolution hooks (for when we want to fallback to the previous resolution - we then need
 * a way to "reset" the environment temporarily)
 */

let enableNativeHooks = true;

/**
 * Simple helper function that assign an error code to an error, so that it can more easily be caught and used
 * by third-parties.
 */

function makeError(code, message, data = {}) {
  const error = new Error(message);
  return Object.assign(error, {code, data});
}

/**
 * Ensures that the returned locator isn't a blacklisted one.
 *
 * Blacklisted packages are packages that cannot be used because their dependencies cannot be deduced. This only
 * happens with peer dependencies, which effectively have different sets of dependencies depending on their parents.
 *
 * In order to deambiguate those different sets of dependencies, the Yarn implementation of PnP will generate a
 * symlink for each combination of <package name>/<package version>/<dependent package> it will find, and will
 * blacklist the target of those symlinks. By doing this, we ensure that files loaded through a specific path
 * will always have the same set of dependencies, provided the symlinks are correctly preserved.
 *
 * Unfortunately, some tools do not preserve them, and when it happens PnP isn't able anymore to deduce the set of
 * dependencies based on the path of the file that makes the require calls. But since we've blacklisted those paths,
 * we're able to print a more helpful error message that points out that a third-party package is doing something
 * incompatible!
 */

// eslint-disable-next-line no-unused-vars
function blacklistCheck(locator) {
  if (locator === blacklistedLocator) {
    throw makeError(
      `BLACKLISTED`,
      [
        `A package has been resolved through a blacklisted path - this is usually caused by one of your tools calling`,
        `"realpath" on the return value of "require.resolve". Since the returned values use symlinks to disambiguate`,
        `peer dependencies, they must be passed untransformed to "require".`,
      ].join(` `),
    );
  }

  return locator;
}

let packageInformationStores = new Map([
["@esy-ocaml/reason",
new Map([["github:facebook/reason:reason.json#ede1f25c895ac9c6a93f7d3c87a19eaa8de366f0",
         {
           packageLocation: "/Users/ulrik.strid/.esy/source/i/esy_ocaml__s__reason__888150f2/",
           packageDependencies: new Map([["@esy-ocaml/reason",
                                         "github:facebook/reason:reason.json#ede1f25c895ac9c6a93f7d3c87a19eaa8de366f0"],
                                           ["@opam/dune", "opam:1.11.4"],
                                           ["@opam/fix", "opam:20181206"],
                                           ["@opam/menhir", "opam:20190924"],
                                           ["@opam/merlin-extend",
                                           "opam:0.5"],
                                           ["@opam/ocaml-migrate-parsetree",
                                           "opam:1.5.0"],
                                           ["@opam/ocamlfind", "opam:1.8.1"],
                                           ["@opam/result", "opam:1.4"],
                                           ["ocaml", "4.9.0"]])}]])],
  ["@esy-ocaml/substs",
  new Map([["0.0.1",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/esy_ocaml__s__substs__0.0.1__19de1ee1/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"]])}]])],
  ["@opam/asn1-combinators",
  new Map([["opam:0.2.0-1",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__asn1_combinators__opam__c__0.2.0_1__a060b65b/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/asn1-combinators",
                                             "opam:0.2.0-1"],
                                             ["@opam/bigarray-compat",
                                             "opam:1.0.0"],
                                             ["@opam/cstruct", "opam:5.1.1"],
                                             ["@opam/ocamlbuild",
                                             "opam:0.14.0"],
                                             ["@opam/ocamlfind",
                                             "opam:1.8.1"],
                                             ["@opam/ptime", "opam:0.8.5"],
                                             ["@opam/result", "opam:1.4"],
                                             ["@opam/topkg", "opam:1.0.1"],
                                             ["@opam/zarith", "opam:1.9.1"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/astring",
  new Map([["opam:0.8.3",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__astring__opam__c__0.8.3__3d7df80e/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/astring", "opam:0.8.3"],
                                             ["@opam/base-bytes",
                                             "opam:base"],
                                             ["@opam/ocamlbuild",
                                             "opam:0.14.0"],
                                             ["@opam/ocamlfind",
                                             "opam:1.8.1"],
                                             ["@opam/topkg", "opam:1.0.1"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/atd",
  new Map([["opam:2.0.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__atd__opam__c__2.0.0__b632d97c/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/atd", "opam:2.0.0"],
                                             ["@opam/easy-format",
                                             "opam:1.3.2"],
                                             ["@opam/jbuilder",
                                             "opam:transition"],
                                             ["@opam/menhir",
                                             "opam:20190924"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/atdgen",
  new Map([["opam:2.0.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__atdgen__opam__c__2.0.0__ce54a24a/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/atd", "opam:2.0.0"],
                                             ["@opam/atdgen", "opam:2.0.0"],
                                             ["@opam/atdgen-runtime",
                                             "opam:2.0.0"],
                                             ["@opam/biniou", "opam:1.2.1"],
                                             ["@opam/jbuilder",
                                             "opam:transition"],
                                             ["@opam/yojson", "opam:1.7.0"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/atdgen-runtime",
  new Map([["opam:2.0.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__atdgen_runtime__opam__c__2.0.0__2d033876/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/atdgen-runtime",
                                             "opam:2.0.0"],
                                             ["@opam/biniou", "opam:1.2.1"],
                                             ["@opam/jbuilder",
                                             "opam:transition"],
                                             ["@opam/yojson", "opam:1.7.0"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/base",
  new Map([["opam:v0.13.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__base__opam__c__v0.13.0__7e765dc2/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/base", "opam:v0.13.0"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/dune-configurator",
                                             "opam:1.0.0"],
                                             ["@opam/sexplib0",
                                             "opam:v0.13.0"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/base-bytes",
  new Map([["opam:base",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__base_bytes__opam__c__base__48b6019a/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/base-bytes",
                                             "opam:base"],
                                             ["@opam/ocamlfind",
                                             "opam:1.8.1"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/base-threads",
  new Map([["opam:base",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__base_threads__opam__c__base__f282958b/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/base-threads",
                                             "opam:base"]])}]])],
  ["@opam/base-unix",
  new Map([["opam:base",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__base_unix__opam__c__base__93427a57/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/base-unix", "opam:base"]])}]])],
  ["@opam/base64",
  new Map([["opam:3.2.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__base64__opam__c__3.2.0__40c4310e/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/base-bytes",
                                             "opam:base"],
                                             ["@opam/base64", "opam:3.2.0"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/bigarray-compat",
  new Map([["opam:1.0.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__bigarray_compat__opam__c__1.0.0__9d53fd01/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/bigarray-compat",
                                             "opam:1.0.0"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/biniou",
  new Map([["opam:1.2.1",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__biniou__opam__c__1.2.1__b33b4deb/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/biniou", "opam:1.2.1"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/easy-format",
                                             "opam:1.3.2"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/cmdliner",
  new Map([["opam:1.0.4",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__cmdliner__opam__c__1.0.4__11482f41/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/cmdliner", "opam:1.0.4"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/conf-gmp",
  new Map([["opam:1",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__conf_gmp__opam__c__1__157c27ec/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/conf-gmp", "opam:1"],
                                             ["esy-gmp",
                                             "archive:https://gmplib.org/download/gmp/gmp-6.1.2.tar.xz#sha1:9dc6981197a7d92f339192eea974f5eca48fcffe"]])}]])],
  ["@opam/conf-m4",
  new Map([["opam:1",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__conf_m4__opam__c__1__7031fb84/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/conf-m4", "opam:1"]])}]])],
  ["@opam/conf-perl",
  new Map([["opam:1",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__conf_perl__opam__c__1__7dcc6eb9/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/conf-perl", "opam:1"]])}]])],
  ["@opam/containers",
  new Map([["opam:2.8",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__containers__opam__c__2.8__4ed5e315/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/base-threads",
                                             "opam:base"],
                                             ["@opam/base-unix", "opam:base"],
                                             ["@opam/containers", "opam:2.8"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/dune-configurator",
                                             "opam:1.0.0"],
                                             ["@opam/seq", "opam:base"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/cppo",
  new Map([["opam:1.6.6",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__cppo__opam__c__1.6.6__df887bb2/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/base-unix", "opam:base"],
                                             ["@opam/cppo", "opam:1.6.6"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/cpuid",
  new Map([["opam:0.1.2",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__cpuid__opam__c__0.1.2__bc096a00/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/cpuid", "opam:0.1.2"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/cstruct",
  new Map([["opam:5.1.1",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__cstruct__opam__c__5.1.1__1c41588c/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/bigarray-compat",
                                             "opam:1.0.0"],
                                             ["@opam/cstruct", "opam:5.1.1"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/domain-name",
  new Map([["opam:0.3.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__domain_name__opam__c__0.3.0__56b77fb8/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/astring", "opam:0.8.3"],
                                             ["@opam/domain-name",
                                             "opam:0.3.0"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/fmt", "opam:0.8.8"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/dune",
  new Map([["opam:1.11.4",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__dune__opam__c__1.11.4__7815d6f1/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/base-threads",
                                             "opam:base"],
                                             ["@opam/base-unix", "opam:base"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/dune-configurator",
  new Map([["opam:1.0.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__dune_configurator__opam__c__1.0.0__1ed35223/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/dune-configurator",
                                             "opam:1.0.0"]])}]])],
  ["@opam/easy-format",
  new Map([["opam:1.3.2",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__easy_format__opam__c__1.3.2__f5ebc92b/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/easy-format",
                                             "opam:1.3.2"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/fix",
  new Map([["opam:20181206",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__fix__opam__c__20181206__69cc3ff1/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/fix", "opam:20181206"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/fmt",
  new Map([["opam:0.8.8",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__fmt__opam__c__0.8.8__81d71639/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/base-unix", "opam:base"],
                                             ["@opam/cmdliner", "opam:1.0.4"],
                                             ["@opam/fmt", "opam:0.8.8"],
                                             ["@opam/ocamlbuild",
                                             "opam:0.14.0"],
                                             ["@opam/ocamlfind",
                                             "opam:1.8.1"],
                                             ["@opam/seq", "opam:base"],
                                             ["@opam/stdlib-shims",
                                             "opam:0.1.0"],
                                             ["@opam/topkg", "opam:1.0.1"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/fpath",
  new Map([["opam:0.7.2",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__fpath__opam__c__0.7.2__d7c490cc/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/astring", "opam:0.8.3"],
                                             ["@opam/fpath", "opam:0.7.2"],
                                             ["@opam/ocamlbuild",
                                             "opam:0.14.0"],
                                             ["@opam/ocamlfind",
                                             "opam:1.8.1"],
                                             ["@opam/result", "opam:1.4"],
                                             ["@opam/topkg", "opam:1.0.1"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/gmap",
  new Map([["opam:0.3.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__gmap__opam__c__0.3.0__1836c421/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/gmap", "opam:0.3.0"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/hex",
  new Map([["opam:1.4.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__hex__opam__c__1.4.0__433c1f4e/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/bigarray-compat",
                                             "opam:1.0.0"],
                                             ["@opam/cstruct", "opam:5.1.1"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/hex", "opam:1.4.0"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/jbuilder",
  new Map([["opam:transition",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__jbuilder__opam__c__transition__90401214/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/jbuilder",
                                             "opam:transition"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/junit",
  new Map([["opam:2.0.1",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__junit__opam__c__2.0.1__0ea3ef9f/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/junit", "opam:2.0.1"],
                                             ["@opam/ptime", "opam:0.8.5"],
                                             ["@opam/tyxml", "opam:4.3.0"]])}]])],
  ["@opam/lwt",
  new Map([["opam:5.1.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__lwt__opam__c__5.1.0__e6ccba6a/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/base-threads",
                                             "opam:base"],
                                             ["@opam/base-unix", "opam:base"],
                                             ["@opam/cppo", "opam:1.6.6"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/dune-configurator",
                                             "opam:1.0.0"],
                                             ["@opam/lwt", "opam:5.1.0"],
                                             ["@opam/mmap", "opam:1.1.0"],
                                             ["@opam/ocplib-endian",
                                             "opam:1.0"],
                                             ["@opam/result", "opam:1.4"],
                                             ["@opam/seq", "opam:base"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/menhir",
  new Map([["opam:20190924",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__menhir__opam__c__20190924__cffc2327/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/menhir",
                                             "opam:20190924"],
                                             ["@opam/ocamlbuild",
                                             "opam:0.14.0"],
                                             ["@opam/ocamlfind",
                                             "opam:1.8.1"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/merlin",
  new Map([["opam:3.3.3",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__merlin__opam__c__3.3.3__4f09323c/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/merlin", "opam:3.3.3"],
                                             ["@opam/ocamlfind",
                                             "opam:1.8.1"],
                                             ["@opam/yojson", "opam:1.7.0"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/merlin-extend",
  new Map([["opam:0.5",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__merlin_extend__opam__c__0.5__d71a3621/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/cppo", "opam:1.6.6"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/merlin-extend",
                                             "opam:0.5"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/mirage-no-solo5",
  new Map([["opam:1",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__mirage_no_solo5__opam__c__1__0dfe7436/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/mirage-no-solo5",
                                             "opam:1"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/mirage-no-xen",
  new Map([["opam:1",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__mirage_no_xen__opam__c__1__5b4fa424/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/mirage-no-xen",
                                             "opam:1"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/mmap",
  new Map([["opam:1.1.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__mmap__opam__c__1.1.0__2cba59f8/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/mmap", "opam:1.1.0"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/nocrypto",
  new Map([["github:mirleft/ocaml-nocrypto:nocrypto.opam#80b7b4b9bd1ccfba3ec93d85cd82bfb3dc10f887",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__nocrypto__691aa5c1/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/cpuid", "opam:0.1.2"],
                                             ["@opam/cstruct", "opam:5.1.1"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/lwt", "opam:5.1.0"],
                                             ["@opam/mirage-no-solo5",
                                             "opam:1"],
                                             ["@opam/mirage-no-xen",
                                             "opam:1"],
                                             ["@opam/nocrypto",
                                             "github:mirleft/ocaml-nocrypto:nocrypto.opam#80b7b4b9bd1ccfba3ec93d85cd82bfb3dc10f887"],
                                             ["@opam/ocplib-endian",
                                             "opam:1.0"],
                                             ["@opam/zarith", "opam:1.9.1"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/ocaml-migrate-parsetree",
  new Map([["opam:1.5.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__ocaml_migrate_parsetree__opam__c__1.5.0__ef212ce2/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/ocaml-migrate-parsetree",
                                             "opam:1.5.0"],
                                             ["@opam/ppx_derivers",
                                             "opam:1.2.1"],
                                             ["@opam/result", "opam:1.4"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/ocamlbuild",
  new Map([["opam:0.14.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__ocamlbuild__opam__c__0.14.0__aff6a0b0/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/ocamlbuild",
                                             "opam:0.14.0"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/ocamlfind",
  new Map([["opam:1.8.1",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__ocamlfind__opam__c__1.8.1__0bdaf9d3/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/conf-m4", "opam:1"],
                                             ["@opam/ocamlfind",
                                             "opam:1.8.1"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/ocamlformat",
  new Map([["opam:0.12",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__ocamlformat__opam__c__0.12__16ff2990/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/base", "opam:v0.13.0"],
                                             ["@opam/base-unix", "opam:base"],
                                             ["@opam/cmdliner", "opam:1.0.4"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/fpath", "opam:0.7.2"],
                                             ["@opam/ocaml-migrate-parsetree",
                                             "opam:1.5.0"],
                                             ["@opam/ocamlformat",
                                             "opam:0.12"],
                                             ["@opam/odoc", "opam:1.4.2"],
                                             ["@opam/re", "opam:1.9.0"],
                                             ["@opam/stdio", "opam:v0.13.0"],
                                             ["@opam/uuseg", "opam:12.0.0"],
                                             ["@opam/uutf", "opam:1.0.2"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/ocplib-endian",
  new Map([["opam:1.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__ocplib_endian__opam__c__1.0__aceff5fc/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/base-bytes",
                                             "opam:base"],
                                             ["@opam/cppo", "opam:1.6.6"],
                                             ["@opam/ocamlbuild",
                                             "opam:0.14.0"],
                                             ["@opam/ocamlfind",
                                             "opam:1.8.1"],
                                             ["@opam/ocplib-endian",
                                             "opam:1.0"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/odoc",
  new Map([["opam:1.4.2",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__odoc__opam__c__1.4.2__10057d49/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/astring", "opam:0.8.3"],
                                             ["@opam/cmdliner", "opam:1.0.4"],
                                             ["@opam/cppo", "opam:1.6.6"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/fpath", "opam:0.7.2"],
                                             ["@opam/odoc", "opam:1.4.2"],
                                             ["@opam/result", "opam:1.4"],
                                             ["@opam/tyxml", "opam:4.3.0"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/ppx_derivers",
  new Map([["opam:1.2.1",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__ppx__derivers__opam__c__1.2.1__a5e0f03f/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/ppx_derivers",
                                             "opam:1.2.1"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/ppx_deriving",
  new Map([["opam:4.4",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__ppx__deriving__opam__c__4.4__34cb5bf2/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/cppo", "opam:1.6.6"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/ocaml-migrate-parsetree",
                                             "opam:1.5.0"],
                                             ["@opam/ppx_derivers",
                                             "opam:1.2.1"],
                                             ["@opam/ppx_deriving",
                                             "opam:4.4"],
                                             ["@opam/ppx_tools",
                                             "opam:5.3+4.08.0"],
                                             ["@opam/ppxfind", "opam:1.3"],
                                             ["@opam/result", "opam:1.4"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/ppx_deriving_yojson",
  new Map([["opam:3.5.1",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__ppx__deriving__yojson__opam__c__3.5.1__8f502955/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/cppo", "opam:1.6.6"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/ppx_deriving",
                                             "opam:4.4"],
                                             ["@opam/ppx_deriving_yojson",
                                             "opam:3.5.1"],
                                             ["@opam/ppx_tools",
                                             "opam:5.3+4.08.0"],
                                             ["@opam/ppxfind", "opam:1.3"],
                                             ["@opam/result", "opam:1.4"],
                                             ["@opam/yojson", "opam:1.7.0"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/ppx_tools",
  new Map([["opam:5.3+4.08.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__ppx__tools__opam__c__5.3+4.08.0__8f54b8bd/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/ocamlfind",
                                             "opam:1.8.1"],
                                             ["@opam/ppx_tools",
                                             "opam:5.3+4.08.0"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/ppxfind",
  new Map([["opam:1.3",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__ppxfind__opam__c__1.3__1f0f8977/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/ocaml-migrate-parsetree",
                                             "opam:1.5.0"],
                                             ["@opam/ocamlfind",
                                             "opam:1.8.1"],
                                             ["@opam/ppxfind", "opam:1.3"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/ptime",
  new Map([["opam:0.8.5",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__ptime__opam__c__0.8.5__79d19c69/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/ocamlbuild",
                                             "opam:0.14.0"],
                                             ["@opam/ocamlfind",
                                             "opam:1.8.1"],
                                             ["@opam/ptime", "opam:0.8.5"],
                                             ["@opam/result", "opam:1.4"],
                                             ["@opam/topkg", "opam:1.0.1"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/re",
  new Map([["opam:1.9.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__re__opam__c__1.9.0__0f723101/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/re", "opam:1.9.0"],
                                             ["@opam/seq", "opam:base"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/result",
  new Map([["opam:1.4",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__result__opam__c__1.4__51db07da/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/result", "opam:1.4"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/rresult",
  new Map([["opam:0.6.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__rresult__opam__c__0.6.0__108d9e8f/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/ocamlbuild",
                                             "opam:0.14.0"],
                                             ["@opam/ocamlfind",
                                             "opam:1.8.1"],
                                             ["@opam/result", "opam:1.4"],
                                             ["@opam/rresult", "opam:0.6.0"],
                                             ["@opam/topkg", "opam:1.0.1"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/seq",
  new Map([["opam:base",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__seq__opam__c__base__a0c677b1/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/seq", "opam:base"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/sexplib0",
  new Map([["opam:v0.13.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__sexplib0__opam__c__v0.13.0__7f6e9078/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/sexplib0",
                                             "opam:v0.13.0"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/stdio",
  new Map([["opam:v0.13.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__stdio__opam__c__v0.13.0__d7d39043/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/base", "opam:v0.13.0"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/stdio", "opam:v0.13.0"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/stdlib-shims",
  new Map([["opam:0.1.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__stdlib_shims__opam__c__0.1.0__0eb3c4d9/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/stdlib-shims",
                                             "opam:0.1.0"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/topkg",
  new Map([["opam:1.0.1",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__topkg__opam__c__1.0.1__52846a4c/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/ocamlbuild",
                                             "opam:0.14.0"],
                                             ["@opam/ocamlfind",
                                             "opam:1.8.1"],
                                             ["@opam/topkg", "opam:1.0.1"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/tyxml",
  new Map([["opam:4.3.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__tyxml__opam__c__4.3.0__8f4dc81b/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/re", "opam:1.9.0"],
                                             ["@opam/seq", "opam:base"],
                                             ["@opam/tyxml", "opam:4.3.0"],
                                             ["@opam/uutf", "opam:1.0.2"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/uchar",
  new Map([["opam:0.0.2",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__uchar__opam__c__0.0.2__d1ad73a0/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/ocamlbuild",
                                             "opam:0.14.0"],
                                             ["@opam/uchar", "opam:0.0.2"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/uucp",
  new Map([["opam:12.0.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__uucp__opam__c__12.0.0__b527873d/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/cmdliner", "opam:1.0.4"],
                                             ["@opam/ocamlbuild",
                                             "opam:0.14.0"],
                                             ["@opam/ocamlfind",
                                             "opam:1.8.1"],
                                             ["@opam/topkg", "opam:1.0.1"],
                                             ["@opam/uchar", "opam:0.0.2"],
                                             ["@opam/uucp", "opam:12.0.0"],
                                             ["@opam/uutf", "opam:1.0.2"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/uuseg",
  new Map([["opam:12.0.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__uuseg__opam__c__12.0.0__eb4863c1/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/cmdliner", "opam:1.0.4"],
                                             ["@opam/ocamlbuild",
                                             "opam:0.14.0"],
                                             ["@opam/ocamlfind",
                                             "opam:1.8.1"],
                                             ["@opam/topkg", "opam:1.0.1"],
                                             ["@opam/uchar", "opam:0.0.2"],
                                             ["@opam/uucp", "opam:12.0.0"],
                                             ["@opam/uuseg", "opam:12.0.0"],
                                             ["@opam/uutf", "opam:1.0.2"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/uutf",
  new Map([["opam:1.0.2",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__uutf__opam__c__1.0.2__34474f09/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/cmdliner", "opam:1.0.4"],
                                             ["@opam/ocamlbuild",
                                             "opam:0.14.0"],
                                             ["@opam/ocamlfind",
                                             "opam:1.8.1"],
                                             ["@opam/topkg", "opam:1.0.1"],
                                             ["@opam/uchar", "opam:0.0.2"],
                                             ["@opam/uutf", "opam:1.0.2"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/x509",
  new Map([["opam:0.8.1",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__x509__opam__c__0.8.1__dd3c6ce4/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/asn1-combinators",
                                             "opam:0.2.0-1"],
                                             ["@opam/cstruct", "opam:5.1.1"],
                                             ["@opam/domain-name",
                                             "opam:0.3.0"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/fmt", "opam:0.8.8"],
                                             ["@opam/gmap", "opam:0.3.0"],
                                             ["@opam/nocrypto",
                                             "github:mirleft/ocaml-nocrypto:nocrypto.opam#80b7b4b9bd1ccfba3ec93d85cd82bfb3dc10f887"],
                                             ["@opam/ptime", "opam:0.8.5"],
                                             ["@opam/rresult", "opam:0.6.0"],
                                             ["@opam/x509", "opam:0.8.1"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/yojson",
  new Map([["opam:1.7.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__yojson__opam__c__1.7.0__397feda6/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/biniou", "opam:1.2.1"],
                                             ["@opam/cppo", "opam:1.6.6"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/easy-format",
                                             "opam:1.3.2"],
                                             ["@opam/yojson", "opam:1.7.0"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@opam/zarith",
  new Map([["opam:1.9.1",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/opam__s__zarith__opam__c__1.9.1__048f9c61/",
             packageDependencies: new Map([["@esy-ocaml/substs", "0.0.1"],
                                             ["@opam/conf-gmp", "opam:1"],
                                             ["@opam/conf-perl", "opam:1"],
                                             ["@opam/ocamlfind",
                                             "opam:1.8.1"],
                                             ["@opam/zarith", "opam:1.9.1"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@reason-native/console",
  new Map([["0.1.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/reason_native__s__console__0.1.0__d4af8f3d/",
             packageDependencies: new Map([["@esy-ocaml/reason",
                                           "github:facebook/reason:reason.json#ede1f25c895ac9c6a93f7d3c87a19eaa8de366f0"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@reason-native/console",
                                             "0.1.0"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@reason-native/file-context-printer",
  new Map([["0.0.3",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/reason_native__s__file_context_printer__0.0.3__9dea979f/",
             packageDependencies: new Map([["@esy-ocaml/reason",
                                           "github:facebook/reason:reason.json#ede1f25c895ac9c6a93f7d3c87a19eaa8de366f0"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/re", "opam:1.9.0"],
                                             ["@reason-native/file-context-printer",
                                             "0.0.3"],
                                             ["@reason-native/pastel",
                                             "0.2.3"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@reason-native/pastel",
  new Map([["0.2.3",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/reason_native__s__pastel__0.2.3__fb4360bc/",
             packageDependencies: new Map([["@esy-ocaml/reason",
                                           "github:facebook/reason:reason.json#ede1f25c895ac9c6a93f7d3c87a19eaa8de366f0"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/re", "opam:1.9.0"],
                                             ["@reason-native/pastel",
                                             "0.2.3"],
                                             ["ocaml", "4.9.0"]])}]])],
  ["@reason-native/rely",
  new Map([["3.1.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/reason_native__s__rely__3.1.0__127b4df7/",
             packageDependencies: new Map([["@esy-ocaml/reason",
                                           "github:facebook/reason:reason.json#ede1f25c895ac9c6a93f7d3c87a19eaa8de366f0"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/junit", "opam:2.0.1"],
                                             ["@opam/re", "opam:1.9.0"],
                                             ["@reason-native/file-context-printer",
                                             "0.0.3"],
                                             ["@reason-native/pastel",
                                             "0.2.3"],
                                             ["@reason-native/rely", "3.1.0"],
                                             ["ocaml", "4.9.0"],
                                             ["refmterr", "3.3.0"]])}]])],
  ["esy-gmp",
  new Map([["archive:https://gmplib.org/download/gmp/gmp-6.1.2.tar.xz#sha1:9dc6981197a7d92f339192eea974f5eca48fcffe",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/esy_gmp__dea0079d/",
             packageDependencies: new Map([["esy-gmp",
                                           "archive:https://gmplib.org/download/gmp/gmp-6.1.2.tar.xz#sha1:9dc6981197a7d92f339192eea974f5eca48fcffe"]])}]])],
  ["ocaml",
  new Map([["4.9.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/ocaml__4.9.0__0ed319e9/",
             packageDependencies: new Map([["ocaml", "4.9.0"]])}]])],
  ["refmterr",
  new Map([["3.3.0",
           {
             packageLocation: "/Users/ulrik.strid/.esy/source/i/refmterr__3.3.0__350d7b3d/",
             packageDependencies: new Map([["@esy-ocaml/reason",
                                           "github:facebook/reason:reason.json#ede1f25c895ac9c6a93f7d3c87a19eaa8de366f0"],
                                             ["@opam/atdgen", "opam:2.0.0"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/re", "opam:1.9.0"],
                                             ["@reason-native/console",
                                             "0.1.0"],
                                             ["@reason-native/pastel",
                                             "0.2.3"],
                                             ["ocaml", "4.9.0"],
                                             ["refmterr", "3.3.0"]])}]])],
  [null,
  new Map([[null,
           {
             packageLocation: "/Users/ulrik.strid/Projects/reason-native-web/reason-jose/",
             packageDependencies: new Map([["@esy-ocaml/reason",
                                           "github:facebook/reason:reason.json#ede1f25c895ac9c6a93f7d3c87a19eaa8de366f0"],
                                             ["@opam/base64", "opam:3.2.0"],
                                             ["@opam/containers", "opam:2.8"],
                                             ["@opam/dune", "opam:1.11.4"],
                                             ["@opam/hex", "opam:1.4.0"],
                                             ["@opam/lwt", "opam:5.1.0"],
                                             ["@opam/merlin", "opam:3.3.3"],
                                             ["@opam/nocrypto",
                                             "github:mirleft/ocaml-nocrypto:nocrypto.opam#80b7b4b9bd1ccfba3ec93d85cd82bfb3dc10f887"],
                                             ["@opam/ocamlformat",
                                             "opam:0.12"],
                                             ["@opam/odoc", "opam:1.4.2"],
                                             ["@opam/ppx_deriving",
                                             "opam:4.4"],
                                             ["@opam/ppx_deriving_yojson",
                                             "opam:3.5.1"],
                                             ["@opam/x509", "opam:0.8.1"],
                                             ["@opam/yojson", "opam:1.7.0"],
                                             ["@reason-native/rely", "3.1.0"],
                                             ["ocaml", "4.9.0"],
                                             ["refmterr", "3.3.0"]])}]])]]);

let locatorsByLocations = new Map([
["../../", topLevelLocator],
  ["../../../../../.esy/source/i/esy_gmp__dea0079d/",
  {
    name: "esy-gmp",
    reference: "archive:https://gmplib.org/download/gmp/gmp-6.1.2.tar.xz#sha1:9dc6981197a7d92f339192eea974f5eca48fcffe"}],
  ["../../../../../.esy/source/i/esy_ocaml__s__reason__888150f2/",
  {
    name: "@esy-ocaml/reason",
    reference: "github:facebook/reason:reason.json#ede1f25c895ac9c6a93f7d3c87a19eaa8de366f0"}],
  ["../../../../../.esy/source/i/esy_ocaml__s__substs__0.0.1__19de1ee1/",
  {
    name: "@esy-ocaml/substs",
    reference: "0.0.1"}],
  ["../../../../../.esy/source/i/ocaml__4.9.0__0ed319e9/",
  {
    name: "ocaml",
    reference: "4.9.0"}],
  ["../../../../../.esy/source/i/opam__s__asn1_combinators__opam__c__0.2.0_1__a060b65b/",
  {
    name: "@opam/asn1-combinators",
    reference: "opam:0.2.0-1"}],
  ["../../../../../.esy/source/i/opam__s__astring__opam__c__0.8.3__3d7df80e/",
  {
    name: "@opam/astring",
    reference: "opam:0.8.3"}],
  ["../../../../../.esy/source/i/opam__s__atd__opam__c__2.0.0__b632d97c/",
  {
    name: "@opam/atd",
    reference: "opam:2.0.0"}],
  ["../../../../../.esy/source/i/opam__s__atdgen__opam__c__2.0.0__ce54a24a/",
  {
    name: "@opam/atdgen",
    reference: "opam:2.0.0"}],
  ["../../../../../.esy/source/i/opam__s__atdgen_runtime__opam__c__2.0.0__2d033876/",
  {
    name: "@opam/atdgen-runtime",
    reference: "opam:2.0.0"}],
  ["../../../../../.esy/source/i/opam__s__base64__opam__c__3.2.0__40c4310e/",
  {
    name: "@opam/base64",
    reference: "opam:3.2.0"}],
  ["../../../../../.esy/source/i/opam__s__base__opam__c__v0.13.0__7e765dc2/",
  {
    name: "@opam/base",
    reference: "opam:v0.13.0"}],
  ["../../../../../.esy/source/i/opam__s__base_bytes__opam__c__base__48b6019a/",
  {
    name: "@opam/base-bytes",
    reference: "opam:base"}],
  ["../../../../../.esy/source/i/opam__s__base_threads__opam__c__base__f282958b/",
  {
    name: "@opam/base-threads",
    reference: "opam:base"}],
  ["../../../../../.esy/source/i/opam__s__base_unix__opam__c__base__93427a57/",
  {
    name: "@opam/base-unix",
    reference: "opam:base"}],
  ["../../../../../.esy/source/i/opam__s__bigarray_compat__opam__c__1.0.0__9d53fd01/",
  {
    name: "@opam/bigarray-compat",
    reference: "opam:1.0.0"}],
  ["../../../../../.esy/source/i/opam__s__biniou__opam__c__1.2.1__b33b4deb/",
  {
    name: "@opam/biniou",
    reference: "opam:1.2.1"}],
  ["../../../../../.esy/source/i/opam__s__cmdliner__opam__c__1.0.4__11482f41/",
  {
    name: "@opam/cmdliner",
    reference: "opam:1.0.4"}],
  ["../../../../../.esy/source/i/opam__s__conf_gmp__opam__c__1__157c27ec/",
  {
    name: "@opam/conf-gmp",
    reference: "opam:1"}],
  ["../../../../../.esy/source/i/opam__s__conf_m4__opam__c__1__7031fb84/",
  {
    name: "@opam/conf-m4",
    reference: "opam:1"}],
  ["../../../../../.esy/source/i/opam__s__conf_perl__opam__c__1__7dcc6eb9/",
  {
    name: "@opam/conf-perl",
    reference: "opam:1"}],
  ["../../../../../.esy/source/i/opam__s__containers__opam__c__2.8__4ed5e315/",
  {
    name: "@opam/containers",
    reference: "opam:2.8"}],
  ["../../../../../.esy/source/i/opam__s__cppo__opam__c__1.6.6__df887bb2/",
  {
    name: "@opam/cppo",
    reference: "opam:1.6.6"}],
  ["../../../../../.esy/source/i/opam__s__cpuid__opam__c__0.1.2__bc096a00/",
  {
    name: "@opam/cpuid",
    reference: "opam:0.1.2"}],
  ["../../../../../.esy/source/i/opam__s__cstruct__opam__c__5.1.1__1c41588c/",
  {
    name: "@opam/cstruct",
    reference: "opam:5.1.1"}],
  ["../../../../../.esy/source/i/opam__s__domain_name__opam__c__0.3.0__56b77fb8/",
  {
    name: "@opam/domain-name",
    reference: "opam:0.3.0"}],
  ["../../../../../.esy/source/i/opam__s__dune__opam__c__1.11.4__7815d6f1/",
  {
    name: "@opam/dune",
    reference: "opam:1.11.4"}],
  ["../../../../../.esy/source/i/opam__s__dune_configurator__opam__c__1.0.0__1ed35223/",
  {
    name: "@opam/dune-configurator",
    reference: "opam:1.0.0"}],
  ["../../../../../.esy/source/i/opam__s__easy_format__opam__c__1.3.2__f5ebc92b/",
  {
    name: "@opam/easy-format",
    reference: "opam:1.3.2"}],
  ["../../../../../.esy/source/i/opam__s__fix__opam__c__20181206__69cc3ff1/",
  {
    name: "@opam/fix",
    reference: "opam:20181206"}],
  ["../../../../../.esy/source/i/opam__s__fmt__opam__c__0.8.8__81d71639/",
  {
    name: "@opam/fmt",
    reference: "opam:0.8.8"}],
  ["../../../../../.esy/source/i/opam__s__fpath__opam__c__0.7.2__d7c490cc/",
  {
    name: "@opam/fpath",
    reference: "opam:0.7.2"}],
  ["../../../../../.esy/source/i/opam__s__gmap__opam__c__0.3.0__1836c421/",
  {
    name: "@opam/gmap",
    reference: "opam:0.3.0"}],
  ["../../../../../.esy/source/i/opam__s__hex__opam__c__1.4.0__433c1f4e/",
  {
    name: "@opam/hex",
    reference: "opam:1.4.0"}],
  ["../../../../../.esy/source/i/opam__s__jbuilder__opam__c__transition__90401214/",
  {
    name: "@opam/jbuilder",
    reference: "opam:transition"}],
  ["../../../../../.esy/source/i/opam__s__junit__opam__c__2.0.1__0ea3ef9f/",
  {
    name: "@opam/junit",
    reference: "opam:2.0.1"}],
  ["../../../../../.esy/source/i/opam__s__lwt__opam__c__5.1.0__e6ccba6a/",
  {
    name: "@opam/lwt",
    reference: "opam:5.1.0"}],
  ["../../../../../.esy/source/i/opam__s__menhir__opam__c__20190924__cffc2327/",
  {
    name: "@opam/menhir",
    reference: "opam:20190924"}],
  ["../../../../../.esy/source/i/opam__s__merlin__opam__c__3.3.3__4f09323c/",
  {
    name: "@opam/merlin",
    reference: "opam:3.3.3"}],
  ["../../../../../.esy/source/i/opam__s__merlin_extend__opam__c__0.5__d71a3621/",
  {
    name: "@opam/merlin-extend",
    reference: "opam:0.5"}],
  ["../../../../../.esy/source/i/opam__s__mirage_no_solo5__opam__c__1__0dfe7436/",
  {
    name: "@opam/mirage-no-solo5",
    reference: "opam:1"}],
  ["../../../../../.esy/source/i/opam__s__mirage_no_xen__opam__c__1__5b4fa424/",
  {
    name: "@opam/mirage-no-xen",
    reference: "opam:1"}],
  ["../../../../../.esy/source/i/opam__s__mmap__opam__c__1.1.0__2cba59f8/",
  {
    name: "@opam/mmap",
    reference: "opam:1.1.0"}],
  ["../../../../../.esy/source/i/opam__s__nocrypto__691aa5c1/",
  {
    name: "@opam/nocrypto",
    reference: "github:mirleft/ocaml-nocrypto:nocrypto.opam#80b7b4b9bd1ccfba3ec93d85cd82bfb3dc10f887"}],
  ["../../../../../.esy/source/i/opam__s__ocaml_migrate_parsetree__opam__c__1.5.0__ef212ce2/",
  {
    name: "@opam/ocaml-migrate-parsetree",
    reference: "opam:1.5.0"}],
  ["../../../../../.esy/source/i/opam__s__ocamlbuild__opam__c__0.14.0__aff6a0b0/",
  {
    name: "@opam/ocamlbuild",
    reference: "opam:0.14.0"}],
  ["../../../../../.esy/source/i/opam__s__ocamlfind__opam__c__1.8.1__0bdaf9d3/",
  {
    name: "@opam/ocamlfind",
    reference: "opam:1.8.1"}],
  ["../../../../../.esy/source/i/opam__s__ocamlformat__opam__c__0.12__16ff2990/",
  {
    name: "@opam/ocamlformat",
    reference: "opam:0.12"}],
  ["../../../../../.esy/source/i/opam__s__ocplib_endian__opam__c__1.0__aceff5fc/",
  {
    name: "@opam/ocplib-endian",
    reference: "opam:1.0"}],
  ["../../../../../.esy/source/i/opam__s__odoc__opam__c__1.4.2__10057d49/",
  {
    name: "@opam/odoc",
    reference: "opam:1.4.2"}],
  ["../../../../../.esy/source/i/opam__s__ppx__derivers__opam__c__1.2.1__a5e0f03f/",
  {
    name: "@opam/ppx_derivers",
    reference: "opam:1.2.1"}],
  ["../../../../../.esy/source/i/opam__s__ppx__deriving__opam__c__4.4__34cb5bf2/",
  {
    name: "@opam/ppx_deriving",
    reference: "opam:4.4"}],
  ["../../../../../.esy/source/i/opam__s__ppx__deriving__yojson__opam__c__3.5.1__8f502955/",
  {
    name: "@opam/ppx_deriving_yojson",
    reference: "opam:3.5.1"}],
  ["../../../../../.esy/source/i/opam__s__ppx__tools__opam__c__5.3+4.08.0__8f54b8bd/",
  {
    name: "@opam/ppx_tools",
    reference: "opam:5.3+4.08.0"}],
  ["../../../../../.esy/source/i/opam__s__ppxfind__opam__c__1.3__1f0f8977/",
  {
    name: "@opam/ppxfind",
    reference: "opam:1.3"}],
  ["../../../../../.esy/source/i/opam__s__ptime__opam__c__0.8.5__79d19c69/",
  {
    name: "@opam/ptime",
    reference: "opam:0.8.5"}],
  ["../../../../../.esy/source/i/opam__s__re__opam__c__1.9.0__0f723101/",
  {
    name: "@opam/re",
    reference: "opam:1.9.0"}],
  ["../../../../../.esy/source/i/opam__s__result__opam__c__1.4__51db07da/",
  {
    name: "@opam/result",
    reference: "opam:1.4"}],
  ["../../../../../.esy/source/i/opam__s__rresult__opam__c__0.6.0__108d9e8f/",
  {
    name: "@opam/rresult",
    reference: "opam:0.6.0"}],
  ["../../../../../.esy/source/i/opam__s__seq__opam__c__base__a0c677b1/",
  {
    name: "@opam/seq",
    reference: "opam:base"}],
  ["../../../../../.esy/source/i/opam__s__sexplib0__opam__c__v0.13.0__7f6e9078/",
  {
    name: "@opam/sexplib0",
    reference: "opam:v0.13.0"}],
  ["../../../../../.esy/source/i/opam__s__stdio__opam__c__v0.13.0__d7d39043/",
  {
    name: "@opam/stdio",
    reference: "opam:v0.13.0"}],
  ["../../../../../.esy/source/i/opam__s__stdlib_shims__opam__c__0.1.0__0eb3c4d9/",
  {
    name: "@opam/stdlib-shims",
    reference: "opam:0.1.0"}],
  ["../../../../../.esy/source/i/opam__s__topkg__opam__c__1.0.1__52846a4c/",
  {
    name: "@opam/topkg",
    reference: "opam:1.0.1"}],
  ["../../../../../.esy/source/i/opam__s__tyxml__opam__c__4.3.0__8f4dc81b/",
  {
    name: "@opam/tyxml",
    reference: "opam:4.3.0"}],
  ["../../../../../.esy/source/i/opam__s__uchar__opam__c__0.0.2__d1ad73a0/",
  {
    name: "@opam/uchar",
    reference: "opam:0.0.2"}],
  ["../../../../../.esy/source/i/opam__s__uucp__opam__c__12.0.0__b527873d/",
  {
    name: "@opam/uucp",
    reference: "opam:12.0.0"}],
  ["../../../../../.esy/source/i/opam__s__uuseg__opam__c__12.0.0__eb4863c1/",
  {
    name: "@opam/uuseg",
    reference: "opam:12.0.0"}],
  ["../../../../../.esy/source/i/opam__s__uutf__opam__c__1.0.2__34474f09/",
  {
    name: "@opam/uutf",
    reference: "opam:1.0.2"}],
  ["../../../../../.esy/source/i/opam__s__x509__opam__c__0.8.1__dd3c6ce4/",
  {
    name: "@opam/x509",
    reference: "opam:0.8.1"}],
  ["../../../../../.esy/source/i/opam__s__yojson__opam__c__1.7.0__397feda6/",
  {
    name: "@opam/yojson",
    reference: "opam:1.7.0"}],
  ["../../../../../.esy/source/i/opam__s__zarith__opam__c__1.9.1__048f9c61/",
  {
    name: "@opam/zarith",
    reference: "opam:1.9.1"}],
  ["../../../../../.esy/source/i/reason_native__s__console__0.1.0__d4af8f3d/",
  {
    name: "@reason-native/console",
    reference: "0.1.0"}],
  ["../../../../../.esy/source/i/reason_native__s__file_context_printer__0.0.3__9dea979f/",
  {
    name: "@reason-native/file-context-printer",
    reference: "0.0.3"}],
  ["../../../../../.esy/source/i/reason_native__s__pastel__0.2.3__fb4360bc/",
  {
    name: "@reason-native/pastel",
    reference: "0.2.3"}],
  ["../../../../../.esy/source/i/reason_native__s__rely__3.1.0__127b4df7/",
  {
    name: "@reason-native/rely",
    reference: "3.1.0"}],
  ["../../../../../.esy/source/i/refmterr__3.3.0__350d7b3d/",
  {
    name: "refmterr",
    reference: "3.3.0"}]]);


  exports.findPackageLocator = function findPackageLocator(location) {
    let relativeLocation = normalizePath(path.relative(__dirname, location));

    if (!relativeLocation.match(isStrictRegExp))
      relativeLocation = `./${relativeLocation}`;

    if (location.match(isDirRegExp) && relativeLocation.charAt(relativeLocation.length - 1) !== '/')
      relativeLocation = `${relativeLocation}/`;

    let match;

  
      if (relativeLocation.length >= 88 && relativeLocation[87] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 88)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 86 && relativeLocation[85] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 86)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 85 && relativeLocation[84] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 85)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 83 && relativeLocation[82] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 83)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 82 && relativeLocation[81] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 82)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 80 && relativeLocation[79] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 80)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 79 && relativeLocation[78] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 79)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 78 && relativeLocation[77] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 78)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 77 && relativeLocation[76] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 77)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 76 && relativeLocation[75] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 76)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 75 && relativeLocation[74] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 75)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 74 && relativeLocation[73] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 74)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 73 && relativeLocation[72] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 73)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 72 && relativeLocation[71] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 72)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 71 && relativeLocation[70] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 71)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 70 && relativeLocation[69] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 70)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 69 && relativeLocation[68] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 69)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 68 && relativeLocation[67] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 68)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 67 && relativeLocation[66] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 67)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 60 && relativeLocation[59] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 60)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 57 && relativeLocation[56] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 57)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 55 && relativeLocation[54] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 55)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 52 && relativeLocation[51] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 52)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 47 && relativeLocation[46] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 47)))
          return blacklistCheck(match);
      

      if (relativeLocation.length >= 6 && relativeLocation[5] === '/')
        if (match = locatorsByLocations.get(relativeLocation.substr(0, 6)))
          return blacklistCheck(match);
      

    return null;
  };
  

/**
 * Returns the module that should be used to resolve require calls. It's usually the direct parent, except if we're
 * inside an eval expression.
 */

function getIssuerModule(parent) {
  let issuer = parent;

  while (issuer && (issuer.id === '[eval]' || issuer.id === '<repl>' || !issuer.filename)) {
    issuer = issuer.parent;
  }

  return issuer;
}

/**
 * Returns information about a package in a safe way (will throw if they cannot be retrieved)
 */

function getPackageInformationSafe(packageLocator) {
  const packageInformation = exports.getPackageInformation(packageLocator);

  if (!packageInformation) {
    throw makeError(
      `INTERNAL`,
      `Couldn't find a matching entry in the dependency tree for the specified parent (this is probably an internal error)`,
    );
  }

  return packageInformation;
}

/**
 * Implements the node resolution for folder access and extension selection
 */

function applyNodeExtensionResolution(unqualifiedPath, {extensions}) {
  // We use this "infinite while" so that we can restart the process as long as we hit package folders
  while (true) {
    let stat;

    try {
      stat = statSync(unqualifiedPath);
    } catch (error) {}

    // If the file exists and is a file, we can stop right there

    if (stat && !stat.isDirectory()) {
      // If the very last component of the resolved path is a symlink to a file, we then resolve it to a file. We only
      // do this first the last component, and not the rest of the path! This allows us to support the case of bin
      // symlinks, where a symlink in "/xyz/pkg-name/.bin/bin-name" will point somewhere else (like "/xyz/pkg-name/index.js").
      // In such a case, we want relative requires to be resolved relative to "/xyz/pkg-name/" rather than "/xyz/pkg-name/.bin/".
      //
      // Also note that the reason we must use readlink on the last component (instead of realpath on the whole path)
      // is that we must preserve the other symlinks, in particular those used by pnp to deambiguate packages using
      // peer dependencies. For example, "/xyz/.pnp/local/pnp-01234569/.bin/bin-name" should see its relative requires
      // be resolved relative to "/xyz/.pnp/local/pnp-0123456789/" rather than "/xyz/pkg-with-peers/", because otherwise
      // we would lose the information that would tell us what are the dependencies of pkg-with-peers relative to its
      // ancestors.

      if (lstatSync(unqualifiedPath).isSymbolicLink()) {
        unqualifiedPath = path.normalize(path.resolve(path.dirname(unqualifiedPath), readlinkSync(unqualifiedPath)));
      }

      return unqualifiedPath;
    }

    // If the file is a directory, we must check if it contains a package.json with a "main" entry

    if (stat && stat.isDirectory()) {
      let pkgJson;

      try {
        pkgJson = JSON.parse(readFileSync(`${unqualifiedPath}/package.json`, 'utf-8'));
      } catch (error) {}

      let nextUnqualifiedPath;

      if (pkgJson && pkgJson.main) {
        nextUnqualifiedPath = path.resolve(unqualifiedPath, pkgJson.main);
      }

      // If the "main" field changed the path, we start again from this new location

      if (nextUnqualifiedPath && nextUnqualifiedPath !== unqualifiedPath) {
        unqualifiedPath = nextUnqualifiedPath;
        continue;
      }
    }

    // Otherwise we check if we find a file that match one of the supported extensions

    const qualifiedPath = extensions
      .map(extension => {
        return `${unqualifiedPath}${extension}`;
      })
      .find(candidateFile => {
        return existsSync(candidateFile);
      });

    if (qualifiedPath) {
      return qualifiedPath;
    }

    // Otherwise, we check if the path is a folder - in such a case, we try to use its index

    if (stat && stat.isDirectory()) {
      const indexPath = extensions
        .map(extension => {
          return `${unqualifiedPath}/index${extension}`;
        })
        .find(candidateFile => {
          return existsSync(candidateFile);
        });

      if (indexPath) {
        return indexPath;
      }
    }

    // Otherwise there's nothing else we can do :(

    return null;
  }
}

/**
 * This function creates fake modules that can be used with the _resolveFilename function.
 * Ideally it would be nice to be able to avoid this, since it causes useless allocations
 * and cannot be cached efficiently (we recompute the nodeModulePaths every time).
 *
 * Fortunately, this should only affect the fallback, and there hopefully shouldn't be a
 * lot of them.
 */

function makeFakeModule(path) {
  const fakeModule = new Module(path, false);
  fakeModule.filename = path;
  fakeModule.paths = Module._nodeModulePaths(path);
  return fakeModule;
}

/**
 * Normalize path to posix format.
 */

// eslint-disable-next-line no-unused-vars
function normalizePath(fsPath) {
  return process.platform === 'win32' ? fsPath.replace(backwardSlashRegExp, '/') : fsPath;
}

/**
 * Forward the resolution to the next resolver (usually the native one)
 */

function callNativeResolution(request, issuer) {
  if (issuer.endsWith('/')) {
    issuer += 'internal.js';
  }

  try {
    enableNativeHooks = false;

    // Since we would need to create a fake module anyway (to call _resolveLookupPath that
    // would give us the paths to give to _resolveFilename), we can as well not use
    // the {paths} option at all, since it internally makes _resolveFilename create another
    // fake module anyway.
    return Module._resolveFilename(request, makeFakeModule(issuer), false);
  } finally {
    enableNativeHooks = true;
  }
}

/**
 * This key indicates which version of the standard is implemented by this resolver. The `std` key is the
 * Plug'n'Play standard, and any other key are third-party extensions. Third-party extensions are not allowed
 * to override the standard, and can only offer new methods.
 *
 * If an new version of the Plug'n'Play standard is released and some extensions conflict with newly added
 * functions, they'll just have to fix the conflicts and bump their own version number.
 */

exports.VERSIONS = {std: 1};

/**
 * Useful when used together with getPackageInformation to fetch information about the top-level package.
 */

exports.topLevel = {name: null, reference: null};

/**
 * Gets the package information for a given locator. Returns null if they cannot be retrieved.
 */

exports.getPackageInformation = function getPackageInformation({name, reference}) {
  const packageInformationStore = packageInformationStores.get(name);

  if (!packageInformationStore) {
    return null;
  }

  const packageInformation = packageInformationStore.get(reference);

  if (!packageInformation) {
    return null;
  }

  return packageInformation;
};

/**
 * Transforms a request (what's typically passed as argument to the require function) into an unqualified path.
 * This path is called "unqualified" because it only changes the package name to the package location on the disk,
 * which means that the end result still cannot be directly accessed (for example, it doesn't try to resolve the
 * file extension, or to resolve directories to their "index.js" content). Use the "resolveUnqualified" function
 * to convert them to fully-qualified paths, or just use "resolveRequest" that do both operations in one go.
 *
 * Note that it is extremely important that the `issuer` path ends with a forward slash if the issuer is to be
 * treated as a folder (ie. "/tmp/foo/" rather than "/tmp/foo" if "foo" is a directory). Otherwise relative
 * imports won't be computed correctly (they'll get resolved relative to "/tmp/" instead of "/tmp/foo/").
 */

exports.resolveToUnqualified = function resolveToUnqualified(request, issuer, {considerBuiltins = true} = {}) {
  // Bailout if the request is a native module

  if (considerBuiltins && builtinModules.has(request)) {
    return null;
  }

  // We allow disabling the pnp resolution for some subpaths. This is because some projects, often legacy,
  // contain multiple levels of dependencies (ie. a yarn.lock inside a subfolder of a yarn.lock). This is
  // typically solved using workspaces, but not all of them have been converted already.

  if (ignorePattern && ignorePattern.test(issuer)) {
    const result = callNativeResolution(request, issuer);

    if (result === false) {
      throw makeError(
        `BUILTIN_NODE_RESOLUTION_FAIL`,
        `The builtin node resolution algorithm was unable to resolve the module referenced by "${request}" and requested from "${issuer}" (it didn't go through the pnp resolver because the issuer was explicitely ignored by the regexp "$$BLACKLIST")`,
        {
          request,
          issuer,
        },
      );
    }

    return result;
  }

  let unqualifiedPath;

  // If the request is a relative or absolute path, we just return it normalized

  const dependencyNameMatch = request.match(pathRegExp);

  if (!dependencyNameMatch) {
    if (path.isAbsolute(request)) {
      unqualifiedPath = path.normalize(request);
    } else if (issuer.match(isDirRegExp)) {
      unqualifiedPath = path.normalize(path.resolve(issuer, request));
    } else {
      unqualifiedPath = path.normalize(path.resolve(path.dirname(issuer), request));
    }
  }

  // Things are more hairy if it's a package require - we then need to figure out which package is needed, and in
  // particular the exact version for the given location on the dependency tree

  if (dependencyNameMatch) {
    const [, dependencyName, subPath] = dependencyNameMatch;

    const issuerLocator = exports.findPackageLocator(issuer);

    // If the issuer file doesn't seem to be owned by a package managed through pnp, then we resort to using the next
    // resolution algorithm in the chain, usually the native Node resolution one

    if (!issuerLocator) {
      const result = callNativeResolution(request, issuer);

      if (result === false) {
        throw makeError(
          `BUILTIN_NODE_RESOLUTION_FAIL`,
          `The builtin node resolution algorithm was unable to resolve the module referenced by "${request}" and requested from "${issuer}" (it didn't go through the pnp resolver because the issuer doesn't seem to be part of the Yarn-managed dependency tree)`,
          {
            request,
            issuer,
          },
        );
      }

      return result;
    }

    const issuerInformation = getPackageInformationSafe(issuerLocator);

    // We obtain the dependency reference in regard to the package that request it

    let dependencyReference = issuerInformation.packageDependencies.get(dependencyName);

    // If we can't find it, we check if we can potentially load it from the packages that have been defined as potential fallbacks.
    // It's a bit of a hack, but it improves compatibility with the existing Node ecosystem. Hopefully we should eventually be able
    // to kill this logic and become stricter once pnp gets enough traction and the affected packages fix themselves.

    if (issuerLocator !== topLevelLocator) {
      for (let t = 0, T = fallbackLocators.length; dependencyReference === undefined && t < T; ++t) {
        const fallbackInformation = getPackageInformationSafe(fallbackLocators[t]);
        dependencyReference = fallbackInformation.packageDependencies.get(dependencyName);
      }
    }

    // If we can't find the path, and if the package making the request is the top-level, we can offer nicer error messages

    if (!dependencyReference) {
      if (dependencyReference === null) {
        if (issuerLocator === topLevelLocator) {
          throw makeError(
            `MISSING_PEER_DEPENDENCY`,
            `You seem to be requiring a peer dependency ("${dependencyName}"), but it is not installed (which might be because you're the top-level package)`,
            {request, issuer, dependencyName},
          );
        } else {
          throw makeError(
            `MISSING_PEER_DEPENDENCY`,
            `Package "${issuerLocator.name}@${issuerLocator.reference}" is trying to access a peer dependency ("${dependencyName}") that should be provided by its direct ancestor but isn't`,
            {request, issuer, issuerLocator: Object.assign({}, issuerLocator), dependencyName},
          );
        }
      } else {
        if (issuerLocator === topLevelLocator) {
          throw makeError(
            `UNDECLARED_DEPENDENCY`,
            `You cannot require a package ("${dependencyName}") that is not declared in your dependencies (via "${issuer}")`,
            {request, issuer, dependencyName},
          );
        } else {
          const candidates = Array.from(issuerInformation.packageDependencies.keys());
          throw makeError(
            `UNDECLARED_DEPENDENCY`,
            `Package "${issuerLocator.name}@${issuerLocator.reference}" (via "${issuer}") is trying to require the package "${dependencyName}" (via "${request}") without it being listed in its dependencies (${candidates.join(
              `, `,
            )})`,
            {request, issuer, issuerLocator: Object.assign({}, issuerLocator), dependencyName, candidates},
          );
        }
      }
    }

    // We need to check that the package exists on the filesystem, because it might not have been installed

    const dependencyLocator = {name: dependencyName, reference: dependencyReference};
    const dependencyInformation = exports.getPackageInformation(dependencyLocator);
    const dependencyLocation = path.resolve(__dirname, dependencyInformation.packageLocation);

    if (!dependencyLocation) {
      throw makeError(
        `MISSING_DEPENDENCY`,
        `Package "${dependencyLocator.name}@${dependencyLocator.reference}" is a valid dependency, but hasn't been installed and thus cannot be required (it might be caused if you install a partial tree, such as on production environments)`,
        {request, issuer, dependencyLocator: Object.assign({}, dependencyLocator)},
      );
    }

    // Now that we know which package we should resolve to, we only have to find out the file location

    if (subPath) {
      unqualifiedPath = path.resolve(dependencyLocation, subPath);
    } else {
      unqualifiedPath = dependencyLocation;
    }
  }

  return path.normalize(unqualifiedPath);
};

/**
 * Transforms an unqualified path into a qualified path by using the Node resolution algorithm (which automatically
 * appends ".js" / ".json", and transforms directory accesses into "index.js").
 */

exports.resolveUnqualified = function resolveUnqualified(
  unqualifiedPath,
  {extensions = Object.keys(Module._extensions)} = {},
) {
  const qualifiedPath = applyNodeExtensionResolution(unqualifiedPath, {extensions});

  if (qualifiedPath) {
    return path.normalize(qualifiedPath);
  } else {
    throw makeError(
      `QUALIFIED_PATH_RESOLUTION_FAILED`,
      `Couldn't find a suitable Node resolution for unqualified path "${unqualifiedPath}"`,
      {unqualifiedPath},
    );
  }
};

/**
 * Transforms a request into a fully qualified path.
 *
 * Note that it is extremely important that the `issuer` path ends with a forward slash if the issuer is to be
 * treated as a folder (ie. "/tmp/foo/" rather than "/tmp/foo" if "foo" is a directory). Otherwise relative
 * imports won't be computed correctly (they'll get resolved relative to "/tmp/" instead of "/tmp/foo/").
 */

exports.resolveRequest = function resolveRequest(request, issuer, {considerBuiltins, extensions} = {}) {
  let unqualifiedPath;

  try {
    unqualifiedPath = exports.resolveToUnqualified(request, issuer, {considerBuiltins});
  } catch (originalError) {
    // If we get a BUILTIN_NODE_RESOLUTION_FAIL error there, it means that we've had to use the builtin node
    // resolution, which usually shouldn't happen. It might be because the user is trying to require something
    // from a path loaded through a symlink (which is not possible, because we need something normalized to
    // figure out which package is making the require call), so we try to make the same request using a fully
    // resolved issuer and throws a better and more actionable error if it works.
    if (originalError.code === `BUILTIN_NODE_RESOLUTION_FAIL`) {
      let realIssuer;

      try {
        realIssuer = realpathSync(issuer);
      } catch (error) {}

      if (realIssuer) {
        if (issuer.endsWith(`/`)) {
          realIssuer = realIssuer.replace(/\/?$/, `/`);
        }

        try {
          exports.resolveToUnqualified(request, realIssuer, {extensions});
        } catch (error) {
          // If an error was thrown, the problem doesn't seem to come from a path not being normalized, so we
          // can just throw the original error which was legit.
          throw originalError;
        }

        // If we reach this stage, it means that resolveToUnqualified didn't fail when using the fully resolved
        // file path, which is very likely caused by a module being invoked through Node with a path not being
        // correctly normalized (ie you should use "node $(realpath script.js)" instead of "node script.js").
        throw makeError(
          `SYMLINKED_PATH_DETECTED`,
          `A pnp module ("${request}") has been required from what seems to be a symlinked path ("${issuer}"). This is not possible, you must ensure that your modules are invoked through their fully resolved path on the filesystem (in this case "${realIssuer}").`,
          {
            request,
            issuer,
            realIssuer,
          },
        );
      }
    }
    throw originalError;
  }

  if (unqualifiedPath === null) {
    return null;
  }

  try {
    return exports.resolveUnqualified(unqualifiedPath);
  } catch (resolutionError) {
    if (resolutionError.code === 'QUALIFIED_PATH_RESOLUTION_FAILED') {
      Object.assign(resolutionError.data, {request, issuer});
    }
    throw resolutionError;
  }
};

/**
 * Setups the hook into the Node environment.
 *
 * From this point on, any call to `require()` will go through the "resolveRequest" function, and the result will
 * be used as path of the file to load.
 */

exports.setup = function setup() {
  // A small note: we don't replace the cache here (and instead use the native one). This is an effort to not
  // break code similar to "delete require.cache[require.resolve(FOO)]", where FOO is a package located outside
  // of the Yarn dependency tree. In this case, we defer the load to the native loader. If we were to replace the
  // cache by our own, the native loader would populate its own cache, which wouldn't be exposed anymore, so the
  // delete call would be broken.

  const originalModuleLoad = Module._load;

  Module._load = function(request, parent, isMain) {
    if (!enableNativeHooks) {
      return originalModuleLoad.call(Module, request, parent, isMain);
    }

    // Builtins are managed by the regular Node loader

    if (builtinModules.has(request)) {
      try {
        enableNativeHooks = false;
        return originalModuleLoad.call(Module, request, parent, isMain);
      } finally {
        enableNativeHooks = true;
      }
    }

    // The 'pnpapi' name is reserved to return the PnP api currently in use by the program

    if (request === `pnpapi`) {
      return pnpModule.exports;
    }

    // Request `Module._resolveFilename` (ie. `resolveRequest`) to tell us which file we should load

    const modulePath = Module._resolveFilename(request, parent, isMain);

    // Check if the module has already been created for the given file

    const cacheEntry = Module._cache[modulePath];

    if (cacheEntry) {
      return cacheEntry.exports;
    }

    // Create a new module and store it into the cache

    const module = new Module(modulePath, parent);
    Module._cache[modulePath] = module;

    // The main module is exposed as global variable

    if (isMain) {
      process.mainModule = module;
      module.id = '.';
    }

    // Try to load the module, and remove it from the cache if it fails

    let hasThrown = true;

    try {
      module.load(modulePath);
      hasThrown = false;
    } finally {
      if (hasThrown) {
        delete Module._cache[modulePath];
      }
    }

    // Some modules might have to be patched for compatibility purposes

    if (patchedModules.has(request)) {
      module.exports = patchedModules.get(request)(module.exports);
    }

    return module.exports;
  };

  const originalModuleResolveFilename = Module._resolveFilename;

  Module._resolveFilename = function(request, parent, isMain, options) {
    if (!enableNativeHooks) {
      return originalModuleResolveFilename.call(Module, request, parent, isMain, options);
    }

    const issuerModule = getIssuerModule(parent);
    const issuer = issuerModule ? issuerModule.filename : process.cwd() + '/';

    const resolution = exports.resolveRequest(request, issuer);
    return resolution !== null ? resolution : request;
  };

  const originalFindPath = Module._findPath;

  Module._findPath = function(request, paths, isMain) {
    if (!enableNativeHooks) {
      return originalFindPath.call(Module, request, paths, isMain);
    }

    for (const path of paths) {
      let resolution;

      try {
        resolution = exports.resolveRequest(request, path);
      } catch (error) {
        continue;
      }

      if (resolution) {
        return resolution;
      }
    }

    return false;
  };

  process.versions.pnp = String(exports.VERSIONS.std);

  if (process.env.ESY__NODE_BIN_PATH != null) {
    const delimiter = require('path').delimiter;
    process.env.PATH = `${process.env.ESY__NODE_BIN_PATH}${delimiter}${process.env.PATH}`;
  }
};

exports.setupCompatibilityLayer = () => {
  // see https://github.com/browserify/resolve/blob/master/lib/caller.js
  const getCaller = () => {
    const origPrepareStackTrace = Error.prepareStackTrace;

    Error.prepareStackTrace = (_, stack) => stack;
    const stack = new Error().stack;
    Error.prepareStackTrace = origPrepareStackTrace;

    return stack[2].getFileName();
  };

  // ESLint currently doesn't have any portable way for shared configs to specify their own
  // plugins that should be used (https://github.com/eslint/eslint/issues/10125). This will
  // likely get fixed at some point, but it'll take time and in the meantime we'll just add
  // additional fallback entries for common shared configs.

  for (const name of [`react-scripts`]) {
    const packageInformationStore = packageInformationStores.get(name);
    if (packageInformationStore) {
      for (const reference of packageInformationStore.keys()) {
        fallbackLocators.push({name, reference});
      }
    }
  }

  // We need to shim the "resolve" module, because Liftoff uses it in order to find the location
  // of the module in the dependency tree. And Liftoff is used to power Gulp, which doesn't work
  // at all unless modulePath is set, which we cannot configure from any other way than through
  // the Liftoff pipeline (the key isn't whitelisted for env or cli options).

  patchedModules.set(/^resolve$/, realResolve => {
    const mustBeShimmed = caller => {
      const callerLocator = exports.findPackageLocator(caller);

      return callerLocator && callerLocator.name === 'liftoff';
    };

    const attachCallerToOptions = (caller, options) => {
      if (!options.basedir) {
        options.basedir = path.dirname(caller);
      }
    };

    const resolveSyncShim = (request, {basedir}) => {
      return exports.resolveRequest(request, basedir, {
        considerBuiltins: false,
      });
    };

    const resolveShim = (request, options, callback) => {
      setImmediate(() => {
        let error;
        let result;

        try {
          result = resolveSyncShim(request, options);
        } catch (thrown) {
          error = thrown;
        }

        callback(error, result);
      });
    };

    return Object.assign(
      (request, options, callback) => {
        if (typeof options === 'function') {
          callback = options;
          options = {};
        } else if (!options) {
          options = {};
        }

        const caller = getCaller();
        attachCallerToOptions(caller, options);

        if (mustBeShimmed(caller)) {
          return resolveShim(request, options, callback);
        } else {
          return realResolve.sync(request, options, callback);
        }
      },
      {
        sync: (request, options) => {
          if (!options) {
            options = {};
          }

          const caller = getCaller();
          attachCallerToOptions(caller, options);

          if (mustBeShimmed(caller)) {
            return resolveSyncShim(request, options);
          } else {
            return realResolve.sync(request, options);
          }
        },
        isCore: request => {
          return realResolve.isCore(request);
        },
      },
    );
  });
};

if (module.parent && module.parent.id === 'internal/preload') {
  exports.setupCompatibilityLayer();

  exports.setup();
}

if (process.mainModule === module) {
  exports.setupCompatibilityLayer();

  const reportError = (code, message, data) => {
    process.stdout.write(`${JSON.stringify([{code, message, data}, null])}\n`);
  };

  const reportSuccess = resolution => {
    process.stdout.write(`${JSON.stringify([null, resolution])}\n`);
  };

  const processResolution = (request, issuer) => {
    try {
      reportSuccess(exports.resolveRequest(request, issuer));
    } catch (error) {
      reportError(error.code, error.message, error.data);
    }
  };

  const processRequest = data => {
    try {
      const [request, issuer] = JSON.parse(data);
      processResolution(request, issuer);
    } catch (error) {
      reportError(`INVALID_JSON`, error.message, error.data);
    }
  };

  if (process.argv.length > 2) {
    if (process.argv.length !== 4) {
      process.stderr.write(`Usage: ${process.argv[0]} ${process.argv[1]} <request> <issuer>\n`);
      process.exitCode = 64; /* EX_USAGE */
    } else {
      processResolution(process.argv[2], process.argv[3]);
    }
  } else {
    let buffer = '';
    const decoder = new StringDecoder.StringDecoder();

    process.stdin.on('data', chunk => {
      buffer += decoder.write(chunk);

      do {
        const index = buffer.indexOf('\n');
        if (index === -1) {
          break;
        }

        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 1);

        processRequest(line);
      } while (true);
    });
  }
}
