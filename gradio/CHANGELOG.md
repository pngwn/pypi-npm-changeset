# gradio-test-pypi

## 0.51.0

### Highlights

#### `AnnotatedImage` Component ([#31](https://github.com/pngwn/pypi-npm-changeset/pull/31) [`c22a53b`](https://github.com/pngwn/pypi-npm-changeset/commit/c22a53bf4cf9d80f69caafa8732cb9ae8db2370f))

New AnnotatedImage component allows users to highlight regions of an image, either by providing bounding boxes, or 0-1 pixel masks. This component is useful for tasks such as image segmentation, object detection, and image captioning.

![AnnotatedImage screenshot](https://user-images.githubusercontent.com/7870876/232142720-86e0020f-beaf-47b9-a843-689c9621f09c.gif)

Example usage:

```python
with gr.Blocks() as demo:
    img = gr.Image()
    img_section = gr.AnnotatedImage()
    def mask(img):
        top_left_corner = [0, 0, 20, 20]
        random_mask = np.random.randint(0, 2, img.shape[:2])
        return (img, [(top_left_corner, "left corner"), (random_mask, "random")])
    img.change(mask, img, img_section)
```

See the [image_segmentation demo](https://github.com/gradio-app/gradio/tree/main/demo/image_segmentation) for a full example.

 Thanks [@pngwn](https://github.com/pngwn)!

### Fixes

- [#32](https://github.com/pngwn/pypi-npm-changeset/pull/32) [`343bda7`](https://github.com/pngwn/pypi-npm-changeset/commit/343bda7ccf39458fb7172693c137e3773f834eea) - update client. Thanks [@pngwn](https://github.com/pngwn)!

## 0.50.0

### Other changes

- Little bitty change

## 0.49.1

### Highlights

Some great big feature
Some great big feature

## 0.49.0

### Features

- this is my change

## 0.48.0

### Features

- A minor change

## 0.47.0

### Features

- A minor change

## 0.46.0

### Features

- A minor change

## 0.45.0

### Features

- A minor change

## 0.44.0

### Features

- A minor change