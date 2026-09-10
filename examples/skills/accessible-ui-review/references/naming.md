# Accessible names

The accessible name is what assistive technology announces for a control. It
is computed, not declared, and the computation has a priority order.

## Priority order

1. `aria-labelledby` (wins over everything; references other elements by id)
2. `aria-label`
3. The native label: `<label for>`, `<caption>`, `<legend>`, `alt`, `title`
   on an `<svg>`
4. The element's own text content
5. `title` attribute (last resort; not announced by every pairing)

If all of these are empty, the control announces as its bare role: "button",
"link". That is a blocker.

## Common failures

| Failure | Why it happens | Fix |
| --- | --- | --- |
| Icon-only button announces "button" | No text content, no label | Add `aria-label`, mark the icon `aria-hidden="true"` |
| Label present but not associated | `<label>` without `for`, or `for` pointing at a missing id | Match `for` to the input `id`, or nest the input inside the label |
| `aria-labelledby` points at nothing | The referenced id was renamed or is rendered conditionally | Verify the id exists whenever the control does |
| Name repeats the role | `aria-label="Save button"` | Drop the role word; it is announced already |
| Link text is "click here" | Written for sighted scanning | Name the destination: "Read the refund policy" |
| Visible label differs from accessible name | `aria-label` overrides visible text | Make the accessible name contain the visible text, or voice control breaks |

## Checking the name

Ask, for each control: if the only thing announced were this name, out of
context, would a user know what it does? If not, the name is wrong even when
it is technically present.

## Groups

Radio groups, checkbox groups and related fieldsets need a group name too.
Use `<fieldset>` with `<legend>`, or `role="group"` with `aria-labelledby`.
An individually-labelled set of radios with no group name leaves the user
without the question they are answering.
