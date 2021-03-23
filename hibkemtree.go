package HIBKEM

import (
	"crypto/rand"
	"errors"
)

//find all the siblings except existing in dup.
//generate private key for each sibling.
func allSiblingsInPath(params *Params, ancestor *PrivateKey, n string, dup []*PrivateKey) ([]*PrivateKey, error) {
	if !IsAncestor(ancestor.ID, n) {
		return nil, errors.New("Not Ancestor!")
	}

	siblings := make([]*PrivateKey, 0)

	ancestorID := ancestor.ID
	sbilingID := ancestor.ID

	for _, ch := range n[len(ancestor.ID):] {
		sbilingID = ancestorID + string(ch^0x1)
		ancestorID = ancestorID + string(ch)

		isNotDup := true
		for _, item := range dup {
			if sbilingID == item.ID {
				isNotDup = false
				break
			}
		}

		if isNotDup {
			move, err := KeyGen(rand.Reader, params, ancestor, sbilingID)
			if err != nil {
				return nil, err
			}
			siblings = append(siblings, move)
		}
	}

	if len(siblings) == 0 {
		return nil, errors.New("All siblings are in the dup set!")
	}

	return siblings, nil
}

// puncture tree
func PunctureTree(params *Params, nodeset []*PrivateKey, n string) ([]*PrivateKey, []*PrivateKey) {
	setPrime := make([]*PrivateKey, 0)
	var oldest *PrivateKey

	j := 0
	for _, item := range nodeset {

		if !IsAncestor(item.ID, n) && !IsDescendant(item.ID, n) && item.ID != n {
			//item would be moved from nodeset to setPrime - step 1
			setPrime = append(setPrime, item)
		} else {
			if IsAncestor(item.ID, n) && (oldest == nil || IsAncestor(item.ID, oldest.ID)) {
				//find the oldest descendant, a tricky workround
				oldest = item
			}
			//item would be moved from nodeset to setPrime - step 2
			nodeset[j] = item
			j++
		}
	}

	if oldest != nil {
		set, _ := allSiblingsInPath(params, oldest, n, setPrime)
		setPrime = append(setPrime, set...)
	}

	return nodeset[:j], setPrime
}
