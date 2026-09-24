"""Image preparation preserves originals and publishes complete validated batches."""
import hashlib
import importlib.util
from pathlib import Path
import sys
import struct
import zlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/revayat-scientific/scripts'
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location('prepare_images', SCRIPTS / 'prepare-figures.py')
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)


def snapshot(directory):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in directory.iterdir() if p.is_file()}


class ImageIntegrityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / '.scratch').mkdir(exist_ok=True)

    def test_collision_preserves_entire_batch(self):
        from PIL import Image
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            work = Path(directory)
            Image.new('RGB', (12, 10), 'red').save(work / 'sample.jpg')
            Image.new('RGBA', (12, 10), (0, 255, 0, 120)).save(work / 'sample.png')
            before = snapshot(work)
            try:
                PREP.main([str(work)])
            except (ValueError, OSError):
                pass
            self.assertEqual(snapshot(work), before)

    def test_depth_frames_and_invalid_profile_refuse_without_mutation(self):
        from PIL import Image
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            work = Path(directory)
            cases = [('depth.tiff', Image.frombytes('I;16', (4, 1), struct.pack('<4H', 256, 512, 1024, 65535)), {}),
                     ('frames.tiff', Image.new('RGB', (5, 5), 'red'),
                      {'save_all': True, 'append_images': [Image.new('RGB', (5, 5), 'blue')]}),
                     ('profile.png', Image.new('RGBA', (5, 5), 'red'), {'icc_profile': b'invalid'})]
            for name, image, options in cases:
                image.save(work / name, **options)
                before = snapshot(work)
                with self.subTest(name=name), self.assertRaises((ValueError, OSError)):
                    PREP.main([str(work / name)])
                self.assertEqual(snapshot(work), before)
                image.close()

    def test_rgb16_png_is_refused_before_lazy_metadata_decodes_pixels(self):
        def chunk(kind, payload):
            return (struct.pack('>I', len(payload)) + kind + payload
                    + struct.pack('>I', zlib.crc32(kind + payload)))
        # Real RGB16 PNG with no EXIF: getexif() otherwise triggers Pillow loading.
        encoded = (b'\x89PNG\r\n\x1a\n'
                   + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 16, 2, 0, 0, 0))
                   + chunk(b'IDAT', zlib.compress(b'\x00' + struct.pack('>HHH', 256, 512, 1024)))
                   + chunk(b'IEND', b''))
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            source = Path(directory) / 'depth.png'
            source.write_bytes(encoded)
            for arguments in ([str(source), '--check'], [str(source), '--invert-dark']):
                with self.subTest(arguments=arguments), self.assertRaisesRegex(ValueError, 'bit depth'):
                    PREP.main(arguments)
                self.assertEqual(source.read_bytes(), encoded)
                self.assertFalse(source.with_name(source.name + '.orig').exists())

    def test_transparency_forms_and_check_only(self):
        from PIL import Image
        variants = [('RGBA', (10, 20, 30, 0), {}), ('LA', (10, 0), {}),
                    ('P', 0, {'transparency': 0}), ('L', 0, {'transparency': 0}),
                    ('RGB', (10, 20, 30), {'transparency': (10, 20, 30)})]
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            work = Path(directory)
            for index, (mode, color, options) in enumerate(variants):
                source = work / f'image-{index}.png'
                Image.new(mode, (8, 6), color).save(source, **options)
                before = source.read_bytes()
                with self.subTest(mode=mode):
                    self.assertEqual(PREP.main([str(source), '--check']), 1)
                    self.assertEqual(source.read_bytes(), before)
                    self.assertEqual(PREP.main([str(source)]), 0)
                    self.assertEqual(source.with_name(source.name + '.orig').read_bytes(), before)
                    with Image.open(source) as image:
                        self.assertEqual(image.mode, 'RGB')
                        self.assertEqual(image.getpixel((0, 0)), (255, 255, 255))
                    self.assertEqual(PREP.main([str(source), '--check']), 0)
                    after = snapshot(work)
                    self.assertEqual(PREP.main([str(source)]), 0)
                    self.assertEqual(snapshot(work), after)

    def test_unsupported_color_and_orientation_metadata_preserve_original(self):
        from PIL import Image, PngImagePlugin
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            work = Path(directory)
            metadata = PngImagePlugin.PngInfo()
            metadata.add(b'gAMA', struct.pack('>I', 45455))
            xmp = PngImagePlugin.PngInfo()
            xmp.add_itxt('XML:com.adobe.xmp', '<tiff:Orientation>6</tiff:Orientation>')
            for name, options in [('gamma.png', {'pnginfo': metadata}),
                                  ('xmp.png', {'pnginfo': xmp})]:
                source = work / name
                exif = Image.Exif()
                exif[274] = 6
                Image.new('RGBA', (8, 4), (20, 30, 40, 100)).save(source, exif=exif, **options)
                before = snapshot(work)
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'metadata'):
                    PREP.main([str(source)])
                self.assertEqual(snapshot(work), before)
            source = work / 'plain-xmp.png'
            Image.new('RGBA', (8, 4), (20, 30, 40, 100)).save(source, pnginfo=xmp)
            self.assertEqual(PREP.main([str(source)]), 0)
            with Image.open(source) as image:
                self.assertEqual(image.info['xmp'], b'<tiff:Orientation>6</tiff:Orientation>')

    def test_metadata_orientation_and_source_preservation(self):
        from PIL import Image, ImageCms, ImageOps
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            work = Path(directory)
            source = work / 'portrait.jpg'
            image = Image.new('RGB', (8, 4), 'red')
            image.putpixel((0, 0), (20, 230, 40))
            exif = Image.Exif()
            exif[274] = 6
            profile = ImageCms.ImageCmsProfile(ImageCms.createProfile('sRGB')).tobytes()
            image.save(source, exif=exif, dpi=(144, 288), icc_profile=profile)
            original = source.read_bytes()
            with Image.open(source) as opened:
                expected = ImageOps.exif_transpose(opened).convert('RGB')
            self.assertEqual(PREP.main([str(source)]), 0)
            self.assertEqual(source.read_bytes(), original)
            with Image.open(source.with_suffix('.png')) as result:
                self.assertEqual(result.size, (4, 8))
                self.assertEqual(result.tobytes(), expected.tobytes())
                self.assertEqual(result.info['icc_profile'], profile)
                self.assertAlmostEqual(result.info['dpi'][0], 288, delta=0.02)
                self.assertAlmostEqual(result.info['dpi'][1], 144, delta=0.02)
                self.assertNotIn(274, result.getexif())

    def test_repeated_arguments_existing_backup_and_unavailable_backend(self):
        from PIL import Image
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            work = Path(directory)
            source = work / 'image.png'
            Image.new('RGBA', (6, 6), (20, 30, 40, 20)).save(source)
            before = snapshot(work)
            for arguments in ([str(source), str(source)], [str(work), str(source)]):
                with self.assertRaises(ValueError):
                    PREP.main(arguments)
                self.assertEqual(snapshot(work), before)
            source.with_name(source.name + '.orig').write_bytes(b'unrelated original')
            before = snapshot(work)
            with self.assertRaises(ValueError):
                PREP.main([str(source)])
            with patch.object(PREP, 'have_pil', return_value=False):
                self.assertEqual(PREP.main([str(source), '--check']), 2)
            self.assertEqual(snapshot(work), before)

    def test_save_and_publication_failure_roll_back_full_batch(self):
        from PIL import Image
        import publication
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            work = Path(directory)
            for name in ('first.png', 'second.png'):
                Image.new('RGBA', (6, 6), (20, 30, 40, 20)).save(work / name)
            before = snapshot(work)
            original_save = PREP.flatten_pil
            def fail_save(source, destination, invert):
                if source.name == 'second.png':
                    raise OSError('injected save failure')
                return original_save(source, destination, invert)
            with patch.object(PREP, 'flatten_pil', side_effect=fail_save), self.assertRaises(OSError):
                PREP.main([str(work)])
            self.assertEqual(snapshot(work), before)
            original_replace = publication.os.replace
            def fail_publish(source, destination):
                if Path(destination).name == 'second.png' and Path(source).name == 'figure.png':
                    raise OSError('injected publication failure')
                return original_replace(source, destination)
            with patch.object(publication.os, 'replace', side_effect=fail_publish), self.assertRaises(OSError):
                PREP.main([str(work)])
            self.assertEqual(snapshot(work), before)
            self.assertFalse(any(p.is_dir() for p in work.iterdir()))


if __name__ == '__main__':
    unittest.main()
