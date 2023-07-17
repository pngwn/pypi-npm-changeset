---
"gradio-test-pypi": minor
---

highlight:

#### `AnnotatedImage` Component

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
