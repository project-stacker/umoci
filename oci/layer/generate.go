/*
 * umoci: Umoci Modifies Open Containers' Images
 * Copyright (C) 2016-2020 SUSE LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package layer

import (
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/apex/log"
	"github.com/opencontainers/umoci/pkg/fseval"
	"github.com/opencontainers/umoci/pkg/unpriv"
	"github.com/pkg/errors"
	"github.com/vbatts/go-mtree"
)

// inodeDeltas is a wrapper around []mtree.InodeDelta that allows for sorting
// the set of deltas by the pathname.
type inodeDeltas []mtree.InodeDelta

func (ids inodeDeltas) Len() int           { return len(ids) }
func (ids inodeDeltas) Less(i, j int) bool { return ids[i].Path() < ids[j].Path() }
func (ids inodeDeltas) Swap(i, j int)      { ids[i], ids[j] = ids[j], ids[i] }

// GenerateLayer creates a new OCI diff layer based on the mtree diff provided.
// All of the mtree.Modified and mtree.Extra blobs are read relative to the
// provided path (which should be the rootfs of the layer that was diffed). The
// returned reader is for the *raw* tar data, it is the caller's responsibility
// to gzip it.
func GenerateLayer(path string, deltas []mtree.InodeDelta, opt *RepackOptions) (io.ReadCloser, error) {
	var packOptions RepackOptions
	if opt != nil {
		packOptions = *opt
	}

	reader, writer := io.Pipe()

	go func() (Err error) {
		// Close with the returned error.
		defer func() {
			if Err != nil {
				log.Warnf("could not generate layer: %v", Err)
			}
			// #nosec G104
			_ = writer.CloseWithError(errors.Wrap(Err, "generate layer"))
		}()

		// We can't just dump all of the file contents into a tar file. We need
		// to emulate a proper tar generator. Luckily there aren't that many
		// things to emulate (and we can do them all in tar.go).
		tg := newTarGenerator(writer, packOptions.MapOptions)

		// Sort the delta paths.
		// FIXME: We need to add whiteouts first, otherwise we might end up
		//        doing something silly like deleting a file which we actually
		//        meant to modify.
		sort.Sort(inodeDeltas(deltas))

		for _, delta := range deltas {
			name := delta.Path()
			fullPath := filepath.Join(path, name)

			// XXX: It's possible that if we unlink a hardlink, we're going to
			//      AddFile() for no reason. Maybe we should drop nlink= from
			//      the set of keywords we care about?

			switch delta.Type() {
			case mtree.Modified, mtree.Extra:
				if packOptions.TranslateOverlayWhiteouts {
					fi, err := os.Stat(fullPath)
					if err != nil {
						return errors.Wrapf(err, "couldn't determine overlay whiteout for %s", fullPath)
					}

					whiteout, err := isOverlayWhiteout(fi, fullPath, tg.fsEval)
					if err != nil {
						return err
					}
					if whiteout {
						if err := tg.AddWhiteout(fullPath); err != nil {
							return errors.Wrap(err, "generate whiteout from overlayfs")
						}
					}
					continue
				}
				if err := tg.AddFile(name, fullPath); err != nil {
					log.Warnf("generate layer: could not add file '%s': %s", name, err)
					return errors.Wrap(err, "generate layer file")
				}
			case mtree.Missing:
				if err := tg.AddWhiteout(name); err != nil {
					log.Warnf("generate layer: could not add whiteout '%s': %s", name, err)
					return errors.Wrap(err, "generate whiteout layer file")
				}
			}
		}

		if err := tg.tw.Close(); err != nil {
			log.Warnf("generate layer: could not close tar.Writer: %s", err)
			return errors.Wrap(err, "close tar writer")
		}

		return nil
	}()

	return reader, nil
}

// exists but not a dir, so what is it?
func isWhiteoutCharDevInPath(ldir string, dir string, fsEval fseval.FsEval) (bool, error) {
	for d := dir; d != "/"; d = filepath.Dir(d) {
		dpath := path.Join(ldir, d)
		dinfo, err := os.Lstat(dpath)
		if err != nil {
			// we expect only not-exists and not-a-dir errors here
			if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) {
				continue
			}

			return false, err
		}

		ok, err := isOverlayWhiteoutCharDev(dinfo, dpath, fsEval)
		if err != nil {
			return false, err
		}

		if !ok {
			continue
		}

		return true, nil
	}

	return false, nil
}

func isPresentInLowerDirs(dir string, lowerDirs []string, fsEval fseval.FsEval) (bool, error) {
	for _, ldir := range lowerDirs {
		p := path.Join(ldir, "overlay", dir)
		_, err := os.Lstat(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}

			if errors.Is(err, syscall.ENOTDIR) {
				// some part of the path is not a dir, and it could be a
				// whiteout char dev
				return isWhiteoutCharDevInPath(path.Join(ldir, "overlay"), dir, fsEval)
			}

			return false, err
		}

		return true, nil
	}

	return false, nil
}

// GenerateInsertLayer generates a completely new layer from "root"to be
// inserted into the image at "target". If "root" is an empty string then the
// "target" will be removed via a whiteout.
func GenerateInsertLayer(root string, target string, opaque bool, opt *RepackOptions) io.ReadCloser {
	root = CleanPath(root)

	var packOptions RepackOptions
	if opt != nil {
		packOptions = *opt
	}

	reader, writer := io.Pipe()

	go func() (Err error) {
		defer func() {
			if Err != nil {
				log.Warnf("could not generate insert layer: %v", Err)
			}
			// #nosec G104
			_ = writer.CloseWithError(errors.Wrap(Err, "generate insert layer"))
		}()

		tg := newTarGenerator(writer, packOptions.MapOptions)

		defer func() {
			if err := tg.tw.Close(); err != nil {
				log.Warnf("generate insert layer: could not close tar.Writer: %s", err)
			}
		}()

		if opaque {
			if err := tg.AddOpaqueWhiteout(target); err != nil {
				return err
			}
		}
		if root == "" {
			return tg.AddWhiteout(target)
		}
		return unpriv.Walk(root, func(curPath string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			pathInTar := path.Join(target, curPath[len(root):])
			whiteout, err := isOverlayWhiteout(info, curPath, tg.fsEval)
			if err != nil {
				return err
			}

			present, err := isPresentInLowerDirs(pathInTar, packOptions.OverlayLowerDirs, tg.fsEval)
			if err != nil {
				return err
			}

			if packOptions.TranslateOverlayWhiteouts && whiteout {
				if present {
					log.Debugf("converting overlayfs whiteout %s to OCI whiteout", pathInTar)
					ret := tg.AddWhiteout(pathInTar)
					if info.IsDir() {
						empty, err := isEmptyDir(curPath)
						if err != nil {
							return err
						}
						if !empty {
							log.Debugf("adding %s since dir is not empty", pathInTar)
							if err := tg.AddFile(pathInTar, curPath); err != nil {
								return err
							}
						}
					}
					return ret
				} else {
					// skip this since previous layers dont have this file/dir
					log.Debugf("skipping whiteout since %s not present in any previous layers", pathInTar)
					return nil
				}
			}

			return tg.AddFile(pathInTar, curPath)
		})
	}()
	return reader
}
