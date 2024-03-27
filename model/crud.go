package model

import "github.com/jinzhu/gorm"

func CreateGroupMPT(db *gorm.DB, groupMPT *GroupMPT) error {
	return db.Create(groupMPT).Error
}

func CreateGroupMarlo(db *gorm.DB, groupMarlo *GroupMarlo) error {
	return db.Create(groupMarlo).Error
}

func ReadGroupMPTs(db *gorm.DB) ([]GroupMPT, error) {
	var groupMPTs []GroupMPT
	err := db.Find(&groupMPTs).Error
	return groupMPTs, err
}

func ReadGroupMarlos(db *gorm.DB) ([]GroupMarlo, error) {
	var groupMarlos []GroupMarlo
	err := db.Find(&groupMarlos).Error
	return groupMarlos, err
}

func UpdateGroupMPT(db *gorm.DB, groupMPT *GroupMPT) error {
	return db.Save(groupMPT).Error
}

func DeleteGroupMarlo(db *gorm.DB, groupMarlo *GroupMarlo) error {
	return db.Delete(groupMarlo).Error
}
